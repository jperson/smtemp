//! End of data: the checks a complete message goes through before it is
//! accepted (bare CR, the From: header and its grants, DKIM, DMARC), then
//! the spool write, the 250, and the fast-path delivery that follows it.

use std::sync::Arc;
use tokio::time::timeout_at;
use tracing::{error, info, warn};

use super::*;

impl UserSession<'_> {
    /// Finish the transaction in progress: run the end-of-data checks,
    /// spool the message with its trace headers, and start the fast-path
    /// delivery. The transaction is taken out of the session first, so it
    /// ends (and the message is counted) whatever the outcome.
    ///
    /// Returns the reply: `250` once the message is durably queued, or the
    /// refusal of the first check that fails (`550`, or `451` for DNS
    /// trouble and a failed spool write); `503` without a transaction.
    pub(super) async fn end_of_data(&mut self) -> smtp::Control {
        let Some(txn) = self.txn.take() else {
            return smtp::Control::reject(NO_RECIPIENTS);
        };
        self.message_count += 1;
        let Transaction {
            mail_from,
            spf_result,
            rcpt_to,
            data: raw,
            ..
        } = txn;
        // `raw` is the message as received: the DATA lines, with line
        // endings exactly as the client sent them.

        // A CR not followed by LF is never valid in an RFC 5322 header
        // block, and readers disagree on it. This
        // server's scanner treats it as ordinary text, while others
        // (Python's `email`, many webmail pipelines) treat it as a line
        // break, so `Subject: x\rFrom: ceo@victim` would hide a second
        // From from the DMARC check while a mail reader shows it. Refuse
        // the message before any other work. The body is not checked.
        if header_has_bare_cr(&raw) {
            warn!("message refused: bare CR in the header block");
            return smtp::Control::reject(BARE_CR_IN_HEADER);
        }
        // Every header scan below (DKIM, the From checks, verdict
        // stripping) holds an entry per field, so their number is bounded
        // before any of them runs.
        if too_many_header_fields(&raw, MAX_HEADER_FIELDS) {
            warn!(
                max = MAX_HEADER_FIELDS,
                "message refused: too many header fields"
            );
            return smtp::Control::reject(TOO_MANY_HEADER_FIELDS);
        }

        // DKIM key lookups and the DMARC policy fetch hold one of this
        // source IP's DNS permits (DESIGN §9). If none frees up in
        // time, the message is refused *temporarily*: skipping the checks
        // instead would fail DMARC and permanently reject legitimate mail.
        let Ok(dns_permit) = self.dns_limit.acquire(self.peer.ip()).await else {
            log_dns_busy("end_of_data");
            return smtp::Control::tempfail(DNS_BUSY);
        };
        // One deadline covers all of this message's DNS work: the DKIM key
        // lookups here and the DMARC policy fetch below.
        let dns_deadline = Instant::now() + self.eod_dns_deadline;
        let keys = match timeout_at(dns_deadline, dkim::fetch_keys(&raw, &self.dns)).await {
            Ok(keys) => keys,
            Err(_) => return self.eod_dns_timed_out("dkim"),
        };
        // Verification is attacker-controlled CPU work (canonicalization
        // and hashing of the whole message, a public-key operation per
        // signature), so it runs on the blocking pool, not on an async
        // worker. The message goes there and comes back, uncopied.
        let verified = tokio::task::spawn_blocking(move || {
            let now = jiff::Timestamp::now().as_second().max(0) as u64;
            let summaries = dkim::verify_with_keys(&raw, &keys, now)
                .iter()
                .map(DkimSummary::from)
                .collect::<Vec<_>>();
            (raw, summaries)
        })
        .await;
        let Ok((raw, dkim_summaries)) = verified else {
            error!("DKIM verification task panicked; refusing with a temporary error");
            return smtp::Control::tempfail(EOD_DNS_TIMEOUT);
        };

        for summary in &dkim_summaries {
            info!(
                domain = %summary.domain,
                selector = %summary.selector,
                dkim_verified = summary.verified,
                body_hash_ok = summary.body_hash_ok,
                signature_ok = summary.signature_ok,
                dkim_error = ?summary.error,
                "dkim verification"
            );
        }
        self.dkim.extend(dkim_summaries.iter().cloned());

        // DMARC (RFC 7489): evaluate the From-header domain against the
        // SPF and DKIM results, and apply the published policy. Authenticated
        // submissions (our own MSA users) are exempt from rejection: an MSA
        // that rejected its own users' mail on DMARC would reject legitimate
        // submissions from networks no SPF record covers. The exemption is
        // conditional by construction: an authenticated message only gets
        // here once its MAIL FROM and every From author passed the login's
        // `--auth-senders` grants (above and in `mail_from`).
        //
        // The From domain is extracted from the raw header bytes, never
        // from the typed parser: a duplicate `From:`, an 8-bit byte in any
        // header, or a grammar failure makes the whole parse fail, and
        // DMARC must still run. RFC 7489 Section 6.6.1: a message with no
        // `From:` or with multiple `From:` headers is rejected, never let
        // through.
        let from_domain = match from_header_domain(&raw) {
            FromHeader::Parsed(domain) => Some(domain),
            problem => {
                warn!(
                    problem = ?problem,
                    "message has no unambiguous From header; rejecting (RFC 7489 Section 6.6.1)"
                );
                return smtp::Control::reject(
                    b"550 5.7.1 Message rejected: missing or malformed From header\r\n",
                );
            }
        };

        // The From authors, on the same tolerant raw scan DMARC uses, so
        // they are the ones a mail client displays.
        let from_value = single_from_value(&raw).ok();
        let authors = from_value.as_deref().and_then(from_authors);
        // A display name naming another organization's address is tagged
        // (a warning header and the spool metadata), never refused: list
        // software does it legitimately.
        let display_name_claims = match (&from_value, &authors) {
            (Some(value), Some(authors)) => display_name_claims(value, authors),
            _ => Vec::new(),
        };
        if !display_name_claims.is_empty() {
            info!(
                claims = ?display_name_claims,
                from_authors = ?authors,
                "From display name names another domain; message tagged"
            );
        }

        // An authenticated session is exempt from DMARC rejection below,
        // which is only safe because every From author must be an address
        // the login owns (`--auth-senders`).
        if let Some(user) = self.authenticated.as_deref() {
            let permitted = match (&authors, self.auth.as_deref()) {
                (Some(authors), Some(auth)) => authors
                    .iter()
                    .all(|(local, domain)| auth.permits(user, local, domain)),
                _ => false,
            };
            if !permitted {
                warn!(
                    auth_user = %user,
                    from_authors = ?authors,
                    "authenticated message refused: From author not granted to this user"
                );
                return smtp::Control::reject(FROM_NOT_OWNED);
            }
        }
        let mut dmarc_summary: Option<DmarcSummary> = None;

        if let Some(from_domain) = from_domain {
            let resolver = spf::DotResolver::shared(self.dns.clone());
            let found = match timeout_at(dns_deadline, dmarc::fetch_policy(&resolver, &from_domain))
                .await
            {
                Err(_) => return self.eod_dns_timed_out("dmarc"),
                Ok(Ok(found)) => found,
                // RFC 7489 §6.6.3: several records at one name means DMARC
                // is not applied. The domain owner's misconfiguration, so
                // loud, but not a reason to defer.
                Ok(Err(dmarc::DmarcError::MultipleRecords)) => {
                    warn!(from_domain = %from_domain, "multiple DMARC records; DMARC not applied");
                    None
                }
                // A failed lookup (SERVFAIL, query timeout) must not count
                // as "no policy": a spoof of a p=reject domain would be
                // delivered whenever its policy couldn't be fetched, which
                // an attacker can provoke by loading the shared resolver.
                // Fail closed: defer, the sender retries.
                Ok(Err(e)) => {
                    warn!(
                        from_domain = %from_domain,
                        error = %e,
                        "dmarc policy lookup failed; temporary failure"
                    );
                    return smtp::Control::tempfail(DMARC_TEMPFAIL);
                }
            };

            if let Some(found) = found {
                let record = &found.record;
                let spf_passed = matches!(spf_result, Some(SpfResult::Pass));
                // The SPF-authenticated domain: the MAIL FROM domain, or for
                // the null sender (a bounce) the HELO domain, which is the
                // identity SPF evaluated (RFC 7208 section 2.4). Address-literal
                // HELOs authenticate no domain.
                let spf_domain = if mail_from.is_empty() {
                    self.helo.as_deref().filter(|h| !h.starts_with('['))
                } else {
                    path_domain(&mail_from)
                };
                // DMARC consumes ONLY this message's DKIM results.
                // `self.dkim` accumulates across the connection for the
                // session log; using it here would let a replayed genuine
                // signature from an earlier message make a later unsigned
                // spoof pass DMARC.
                let dkim: Vec<(String, bool)> = dkim_summaries
                    .iter()
                    .map(|d| (d.domain.clone(), d.verified))
                    .collect();

                let evaluation = dmarc::evaluate(
                    record,
                    spf_domain.map(|d| (d, spf_passed)),
                    &dkim,
                    &from_domain,
                );
                // `sp=` governs a subdomain whose record was inherited
                // from an ancestor (RFC 7489 §6.3).
                let policy = found.policy_for(&from_domain);
                let action = dmarc::apply(&evaluation, policy);

                let summary = DmarcSummary {
                    from_domain: from_domain.clone(),
                    policy,
                    spf_aligned: evaluation.spf_aligned,
                    dkim_aligned: evaluation.dkim_aligned,
                    pass: evaluation.pass,
                    action,
                };
                info!(
                    from_domain = %summary.from_domain,
                    dmarc_policy = summary.policy.as_str(),
                    spf_aligned = summary.spf_aligned,
                    dkim_aligned = summary.dkim_aligned,
                    dmarc_pass = summary.pass,
                    dmarc_action = summary.action.as_str(),
                    "dmarc evaluation"
                );
                self.dmarc = Some(summary.clone());
                dmarc_summary = Some(summary);

                let exempt = self.authenticated.is_some();
                // A signature that could have aligned but whose key lookup
                // got no definite answer might have verified: refusing for
                // good would reject legitimate mail over a DNS hiccup.
                // Defer instead; the sender retries.
                let unresolved = dkim_summaries
                    .iter()
                    .any(|d| d.temporary && dmarc::aligned_relaxed(&d.domain, &from_domain));
                if action == dmarc::Action::Reject && !exempt && unresolved {
                    warn!(
                        from_domain = %from_domain,
                        "dmarc would reject, but a DKIM key lookup failed temporarily; deferring"
                    );
                    return smtp::Control::tempfail(DMARC_TEMPFAIL);
                }
                if action == dmarc::Action::Reject && !exempt {
                    // Rejected mail is not spooled.
                    return smtp::Control::reject(
                        b"550 5.7.1 This message does not comply with the required DMARC policy\r\n",
                    );
                }
            }
        }
        // DNS work for this message is done; the spool write and delivery
        // below must not hold the source IP's DNS share.
        drop(dns_permit);

        // Spool before accepting: the 250 is only sent after a durable
        // write. The backend is blocking (fsync, and object
        // storage later), so it runs on the blocking pool. A failed
        // spool is a temporary failure — the client is invited to
        // retry, nothing is lost.
        // The disk may have filled since MAIL FROM; spooling now could
        // take the space that delivering accepted mail needs.
        if self.storage_is_low() {
            return smtp::Control::tempfail(INSUFFICIENT_STORAGE);
        }

        if let Some(spool) = self.spool.clone() {
            let meta = spool::SpoolMeta {
                // Assigned now, because the Received: header names it.
                queue_id: spool::new_queue_id(),
                session_id: self.session_id.to_string(),
                server_domain: self.domain.to_string(),
                received_at: jiff::Timestamp::now().to_string(),
                peer: self.peer.to_string(),
                helo: self.helo.clone(),
                mail_from: Some(mail_from),
                rcpt_to: rcpt_to.clone(),
                spf_result,
                spf_helo: self.spf_helo,
                dkim: dkim_summaries,
                dmarc: dmarc_summary,
                authenticated: self.authenticated.clone(),
                tls_active: self.tls_active,
                message_size: raw.len(),
                encryption: None, // set by the backend's encryptor, if any
                display_name_claims,
            };
            // The trace headers go in now, once, before the write: the
            // stored payload is the final message for every recipient, so
            // it can be sealed and is delivered verbatim (fast path and
            // drain alike).
            // Our verdict headers go on top; a sender's forged copies of
            // them (claiming this server's authserv-id) are removed first.
            let message =
                delivery::with_trace_headers(&meta, &strip_forged_verdicts(&raw, self.domain));
            // Only the final message is needed from here on: holding the
            // received copy too would double this session's memory while
            // the spool writes.
            drop(raw);
            let queue_id = meta.queue_id.clone();
            let write_spool = spool.clone();
            let write = tokio::task::spawn_blocking(move || write_spool.write(meta, message));
            // What the spool stored (sealed, with an encryptor): the bytes
            // every recipient gets, shared by the delivery tasks below.
            let stored: Arc<Vec<u8>> = match write.await {
                Ok(Ok(stored)) => {
                    info!(queue_id = %queue_id, recipients = rcpt_to.len(), "message spooled");
                    Arc::new(stored.payload)
                }
                Ok(Err(e)) => {
                    error!(error = %e, "spool write failed; refusing with a temporary error");
                    return smtp::Control::tempfail(
                        b"451 4.3.0 Error: queueing failed, try again later\r\n",
                    );
                }
                Err(e) => {
                    error!(error = %e, "spool task panicked; refusing with a temporary error");
                    return smtp::Control::tempfail(
                        b"451 4.3.0 Error: queueing failed, try again later\r\n",
                    );
                }
            };

            // Delivery fast path, for low latency: deliver each recipient's
            // copy now, in the background, so the 250 goes out without
            // waiting for it. Nothing depends on it: the message is
            // durably queued, the drain retries what fails, and delivery
            // is idempotent per (envelope address, queue_id), so a race
            // with the drain never duplicates mail. With every fast-path
            // slot busy, the drain delivers instead.
            if let Some(sink) = self.sink.clone() {
                match Arc::clone(&self.fast_path).try_acquire_owned() {
                    Ok(slot) => {
                        tokio::spawn(async move {
                            fast_path_deliver(sink, spool, rcpt_to, queue_id, stored).await;
                            drop(slot);
                        });
                    }
                    Err(_) => {
                        info!(queue_id = %queue_id, "fast path busy; left for the drain");
                    }
                }
            }
        }

        smtp::Control::accept(UserSession::OK)
    }

    /// End the transaction with a temporary failure because the
    /// end-of-data DNS work ran past [`UserSession::eod_dns_deadline`]
    /// (`stage`: dkim or dmarc). Logged at `warn`, like an SPF deadline.
    ///
    /// Returns the `451` reply.
    fn eod_dns_timed_out(&self, stage: &str) -> smtp::Control {
        warn!(
            stage,
            limit_ms = u64::try_from(self.eod_dns_deadline.as_millis()).unwrap_or(u64::MAX),
            "end-of-data DNS checks exceeded their time limit; temporary failure"
        );
        smtp::Control::tempfail(EOD_DNS_TIMEOUT)
    }
}

/// Fast-path delivery of the stored message `stored` (queue ID
/// `queue_id`): hand each of `recipients` to `sink` on the blocking pool,
/// then dequeue it from `spool` if every copy was delivered. Failures are
/// logged and left queued for the drain.
async fn fast_path_deliver(
    sink: Arc<dyn delivery::DeliverySink>,
    spool: Arc<dyn spool::SpoolWriter>,
    recipients: Vec<spool::SpoolRcpt>,
    queue_id: String,
    stored: Arc<Vec<u8>>,
) {
    let total = recipients.len();
    let mut delivered = 0usize;
    for rcpt in recipients {
        let (address, mailbox) = (rcpt.address.clone(), rcpt.mailbox.clone());
        let attempt = tokio::task::spawn_blocking({
            let (sink, queue_id, stored) = (sink.clone(), queue_id.clone(), Arc::clone(&stored));
            move || sink.deliver(&rcpt, &queue_id, &stored)
        })
        .await;
        match attempt {
            Ok(Ok(())) => {
                delivered += 1;
                info!(queue_id = %queue_id, recipient = %address, mailbox = %mailbox, "message delivered");
            }
            Ok(Err(e)) => {
                warn!(queue_id = %queue_id, recipient = %address, error = %e, "fast-path delivery failed; queued for retry");
            }
            Err(e) => {
                warn!(queue_id = %queue_id, recipient = %address, error = %e, "delivery task panicked; queued for retry");
            }
        }
    }
    if delivered == total {
        let removed = tokio::task::spawn_blocking({
            let queue_id = queue_id.clone();
            move || spool.remove(&queue_id)
        })
        .await;
        match removed {
            Ok(Ok(())) => info!(queue_id = %queue_id, "all recipients delivered; dequeued"),
            // Still queued: the drain finds every copy already delivered
            // (idempotent) and dequeues it then.
            Ok(Err(e)) => warn!(queue_id = %queue_id, error = %e, "dequeue after delivery failed"),
            Err(e) => warn!(queue_id = %queue_id, error = %e, "dequeue task panicked"),
        }
    }
}
