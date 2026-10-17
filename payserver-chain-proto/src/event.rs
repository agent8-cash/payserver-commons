//! Validated domain forms of the wire messages.
//!
//! Every `TryFrom<proto>` here is the validating boundary: it is the only way
//! to obtain these types from the wire, and each failure is a named
//! [`ProtocolError`].

use crate::v1;
use chrono::{DateTime, Utc};

/// Longest amount, in digits: the width of `2^256 - 1`.
pub const MAX_AMOUNT_DIGITS: usize = 78;
/// Longest address or transaction hash accepted, in bytes.
pub const MAX_TEXT_BYTES: usize = 256;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProtocolError {
    #[error("{field}: amount is empty")]
    AmountEmpty { field: &'static str },
    #[error("{field}: amount has {digits} digits, at most {MAX_AMOUNT_DIGITS} allowed")]
    AmountTooLong { field: &'static str, digits: usize },
    #[error("{field}: amount must be ASCII decimal digits only (no sign, point or separator)")]
    AmountNotDigits { field: &'static str },
    #[error("{field}: value is empty")]
    TextEmpty { field: &'static str },
    #[error("{field}: value is {len} bytes, at most {MAX_TEXT_BYTES} allowed")]
    TextTooLong { field: &'static str, len: usize },
    #[error("{field}: value contains whitespace or a control character")]
    TextInvalidChar { field: &'static str },
    #[error("{field}: required message is missing")]
    Missing { field: &'static str },
    #[error("{field}: timestamp is out of range")]
    BadTimestamp { field: &'static str },
    #[error("event carries no payload")]
    EmptyEvent,
    #[error("unknown adapter state {0}")]
    UnknownState(i32),
}

/// A base-unit amount: 1..=78 ASCII digits. Kept as text so no precision is
/// lost and nothing is rewritten; range against a concrete numeric type is the
/// consumer's concern.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Amount(String);

impl Amount {
    pub fn parse(field: &'static str, s: &str) -> Result<Self, ProtocolError> {
        if s.is_empty() {
            return Err(ProtocolError::AmountEmpty { field });
        }
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            return Err(ProtocolError::AmountNotDigits { field });
        }
        if s.len() > MAX_AMOUNT_DIGITS {
            return Err(ProtocolError::AmountTooLong {
                field,
                digits: s.len(),
            });
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical chain text (address, transaction hash, asset id), carried exactly
/// as received. Never case-folded or trimmed.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ChainText(String);

impl ChainText {
    pub fn parse(field: &'static str, s: &str) -> Result<Self, ProtocolError> {
        if s.is_empty() {
            return Err(ProtocolError::TextEmpty { field });
        }
        if s.len() > MAX_TEXT_BYTES {
            return Err(ProtocolError::TextTooLong {
                field,
                len: s.len(),
            });
        }
        if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(ProtocolError::TextInvalidChar { field });
        }
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Opaque ids and the asset field: empty is meaningful (native asset), so only
/// the character rules apply.
fn optional_text(field: &'static str, s: &str) -> Result<Option<ChainText>, ProtocolError> {
    if s.is_empty() {
        Ok(None)
    } else {
        ChainText::parse(field, s).map(Some)
    }
}

fn text_or_empty(t: &Option<ChainText>) -> String {
    t.as_ref().map(|t| t.0.clone()).unwrap_or_default()
}

fn to_ts(t: DateTime<Utc>) -> prost_types::Timestamp {
    prost_types::Timestamp {
        seconds: t.timestamp(),
        nanos: t.timestamp_subsec_nanos() as i32,
    }
}

fn from_ts(
    field: &'static str,
    t: &prost_types::Timestamp,
) -> Result<DateTime<Utc>, ProtocolError> {
    u32::try_from(t.nanos)
        .ok()
        .and_then(|n| DateTime::from_timestamp(t.seconds, n))
        .ok_or(ProtocolError::BadTimestamp { field })
}

fn opt_ts(
    field: &'static str,
    t: &Option<prost_types::Timestamp>,
) -> Result<Option<DateTime<Utc>>, ProtocolError> {
    t.as_ref().map(|t| from_ts(field, t)).transpose()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PaymentRef {
    pub tx_hash: ChainText,
    pub index: u32,
}

impl TryFrom<v1::PaymentRef> for PaymentRef {
    type Error = ProtocolError;
    fn try_from(p: v1::PaymentRef) -> Result<Self, Self::Error> {
        Ok(Self {
            tx_hash: ChainText::parse("tx_hash", &p.tx_hash)?,
            index: p.index,
        })
    }
}

impl From<PaymentRef> for v1::PaymentRef {
    fn from(p: PaymentRef) -> Self {
        Self {
            tx_hash: p.tx_hash.0,
            index: p.index,
        }
    }
}

fn payment(p: Option<v1::PaymentRef>) -> Result<PaymentRef, ProtocolError> {
    p.ok_or(ProtocolError::Missing { field: "payment" })?
        .try_into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterState {
    Healthy,
    Degraded,
    Down,
}

/// What an adapter reports. There is no late-paid variant: that is decided by
/// the orchestrator from the invoice's expiry, which an adapter never sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEventKind {
    PaymentDetected {
        watch_id: Option<ChainText>,
        address: ChainText,
        asset: Option<ChainText>,
        payment: PaymentRef,
        amount: Amount,
    },
    PaymentConfirmed {
        watch_id: Option<ChainText>,
        address: ChainText,
        asset: Option<ChainText>,
        payment: PaymentRef,
        amount: Amount,
        block_height: u64,
        confirmations: u32,
    },
    PaymentReorged {
        retracted: Vec<PaymentRef>,
    },
    ChainProgress {
        height: u64,
        block_time: Option<DateTime<Utc>>,
    },
    AdapterStatus {
        state: AdapterState,
        detail: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainEvent {
    pub seq: u64,
    pub chain_id: ChainText,
    pub kind: ChainEventKind,
}

impl TryFrom<v1::ChainEvent> for ChainEvent {
    type Error = ProtocolError;

    fn try_from(e: v1::ChainEvent) -> Result<Self, Self::Error> {
        use v1::chain_event::Event;
        let kind = match e.event.ok_or(ProtocolError::EmptyEvent)? {
            Event::PaymentDetected(p) => ChainEventKind::PaymentDetected {
                watch_id: optional_text("watch_id", &p.watch_id)?,
                address: ChainText::parse("address", &p.address)?,
                asset: optional_text("asset", &p.asset)?,
                payment: payment(p.payment)?,
                amount: Amount::parse("amount", &p.amount)?,
            },
            Event::PaymentConfirmed(p) => ChainEventKind::PaymentConfirmed {
                watch_id: optional_text("watch_id", &p.watch_id)?,
                address: ChainText::parse("address", &p.address)?,
                asset: optional_text("asset", &p.asset)?,
                payment: payment(p.payment)?,
                amount: Amount::parse("amount", &p.amount)?,
                block_height: p.block_height,
                confirmations: p.confirmations,
            },
            Event::PaymentReorged(p) => ChainEventKind::PaymentReorged {
                retracted: p
                    .retracted
                    .into_iter()
                    .map(PaymentRef::try_from)
                    .collect::<Result<_, _>>()?,
            },
            Event::ChainProgress(p) => ChainEventKind::ChainProgress {
                height: p.height,
                block_time: opt_ts("block_time", &p.block_time)?,
            },
            Event::AdapterStatus(s) => ChainEventKind::AdapterStatus {
                state: match v1::adapter_status::State::try_from(s.state) {
                    Ok(v1::adapter_status::State::Healthy) => AdapterState::Healthy,
                    Ok(v1::adapter_status::State::Degraded) => AdapterState::Degraded,
                    Ok(v1::adapter_status::State::Down) => AdapterState::Down,
                    _ => return Err(ProtocolError::UnknownState(s.state)),
                },
                detail: s.detail,
            },
        };
        Ok(Self {
            seq: e.seq,
            chain_id: ChainText::parse("chain_id", &e.chain_id)?,
            kind,
        })
    }
}

impl From<ChainEvent> for v1::ChainEvent {
    fn from(e: ChainEvent) -> Self {
        use v1::chain_event::Event;
        let event = match e.kind {
            ChainEventKind::PaymentDetected {
                watch_id,
                address,
                asset,
                payment,
                amount,
            } => Event::PaymentDetected(v1::PaymentDetected {
                watch_id: text_or_empty(&watch_id),
                address: address.0,
                asset: text_or_empty(&asset),
                payment: Some(payment.into()),
                amount: amount.0,
            }),
            ChainEventKind::PaymentConfirmed {
                watch_id,
                address,
                asset,
                payment,
                amount,
                block_height,
                confirmations,
            } => Event::PaymentConfirmed(v1::PaymentConfirmed {
                watch_id: text_or_empty(&watch_id),
                address: address.0,
                asset: text_or_empty(&asset),
                payment: Some(payment.into()),
                amount: amount.0,
                block_height,
                confirmations,
            }),
            ChainEventKind::PaymentReorged { retracted } => {
                Event::PaymentReorged(v1::PaymentReorged {
                    retracted: retracted.into_iter().map(Into::into).collect(),
                })
            }
            ChainEventKind::ChainProgress { height, block_time } => {
                Event::ChainProgress(v1::ChainProgress {
                    height,
                    block_time: block_time.map(to_ts),
                })
            }
            ChainEventKind::AdapterStatus { state, detail } => {
                Event::AdapterStatus(v1::AdapterStatus {
                    state: match state {
                        AdapterState::Healthy => v1::adapter_status::State::Healthy,
                        AdapterState::Degraded => v1::adapter_status::State::Degraded,
                        AdapterState::Down => v1::adapter_status::State::Down,
                    } as i32,
                    detail,
                })
            }
        };
        Self {
            seq: e.seq,
            chain_id: e.chain_id.0,
            event: Some(event),
        }
    }
}

/// A validated watch request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchSpec {
    pub chain_id: ChainText,
    pub address: ChainText,
    pub asset: Option<ChainText>,
    pub watch_id: Option<ChainText>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl TryFrom<v1::WatchRequest> for WatchSpec {
    type Error = ProtocolError;
    fn try_from(w: v1::WatchRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            chain_id: ChainText::parse("chain_id", &w.chain_id)?,
            address: ChainText::parse("address", &w.address)?,
            asset: optional_text("asset", &w.asset)?,
            watch_id: optional_text("watch_id", &w.watch_id)?,
            expires_at: opt_ts("expires_at", &w.expires_at)?,
        })
    }
}

impl From<WatchSpec> for v1::WatchRequest {
    fn from(w: WatchSpec) -> Self {
        Self {
            chain_id: w.chain_id.0,
            address: w.address.0,
            asset: text_or_empty(&w.asset),
            watch_id: text_or_empty(&w.watch_id),
            expires_at: w.expires_at.map(to_ts),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use prost::Message;

    fn text() -> impl Strategy<Value = ChainText> {
        // Mixed case on purpose: it must come back byte-identical.
        "[0-9a-zA-Z]{1,64}".prop_map(|s| ChainText::parse("t", &s).unwrap())
    }
    fn opt_text() -> impl Strategy<Value = Option<ChainText>> {
        proptest::option::of(text())
    }
    fn amount() -> impl Strategy<Value = Amount> {
        "[0-9]{1,78}".prop_map(|s| Amount::parse("a", &s).unwrap())
    }
    fn pref() -> impl Strategy<Value = PaymentRef> {
        (text(), any::<u32>()).prop_map(|(tx_hash, index)| PaymentRef { tx_hash, index })
    }
    fn time() -> impl Strategy<Value = Option<DateTime<Utc>>> {
        proptest::option::of(
            (0i64..4_000_000_000, 0u32..1_000_000_000)
                .prop_map(|(s, n)| DateTime::from_timestamp(s, n).unwrap()),
        )
    }
    fn kind() -> impl Strategy<Value = ChainEventKind> {
        prop_oneof![
            (opt_text(), text(), opt_text(), pref(), amount()).prop_map(
                |(watch_id, address, asset, payment, amount)| ChainEventKind::PaymentDetected {
                    watch_id,
                    address,
                    asset,
                    payment,
                    amount
                }
            ),
            (
                (opt_text(), text(), opt_text(), pref(), amount()),
                any::<u64>(),
                any::<u32>()
            )
                .prop_map(
                    |((watch_id, address, asset, payment, amount), block_height, confirmations)| {
                        ChainEventKind::PaymentConfirmed {
                            watch_id,
                            address,
                            asset,
                            payment,
                            amount,
                            block_height,
                            confirmations,
                        }
                    }
                ),
            proptest::collection::vec(pref(), 0..5)
                .prop_map(|retracted| ChainEventKind::PaymentReorged { retracted }),
            (any::<u64>(), time()).prop_map(|(height, block_time)| ChainEventKind::ChainProgress {
                height,
                block_time
            }),
            (
                prop_oneof![
                    Just(AdapterState::Healthy),
                    Just(AdapterState::Degraded),
                    Just(AdapterState::Down)
                ],
                ".{0,40}"
            )
                .prop_map(|(state, detail)| ChainEventKind::AdapterStatus { state, detail }),
        ]
    }
    fn event() -> impl Strategy<Value = ChainEvent> {
        (any::<u64>(), text(), kind()).prop_map(|(seq, chain_id, kind)| ChainEvent {
            seq,
            chain_id,
            kind,
        })
    }

    proptest! {
        #[test]
        fn event_survives_the_wire(ev in event()) {
            let bytes = v1::ChainEvent::from(ev.clone()).encode_to_vec();
            let back = ChainEvent::try_from(v1::ChainEvent::decode(bytes.as_slice()).unwrap());
            prop_assert_eq!(back, Ok(ev));
        }

        #[test]
        fn watch_survives_the_wire(
            chain_id in text(), address in text(), asset in opt_text(),
            watch_id in opt_text(), expires_at in time(),
        ) {
            let w = WatchSpec { chain_id, address, asset, watch_id, expires_at };
            let bytes = v1::WatchRequest::from(w.clone()).encode_to_vec();
            let back = WatchSpec::try_from(v1::WatchRequest::decode(bytes.as_slice()).unwrap());
            prop_assert_eq!(back, Ok(w));
        }
    }

    fn detected(address: &str, amount: &str) -> v1::ChainEvent {
        v1::ChainEvent {
            seq: 1,
            chain_id: "eip155:1".into(),
            event: Some(v1::chain_event::Event::PaymentDetected(
                v1::PaymentDetected {
                    address: address.into(),
                    amount: amount.into(),
                    payment: Some(v1::PaymentRef {
                        tx_hash: "0xAbC".into(),
                        index: 0,
                    }),
                    ..Default::default()
                },
            )),
        }
    }

    #[test]
    fn eighty_digit_amount_is_a_named_error() {
        let err = ChainEvent::try_from(detected("0xabc", &"9".repeat(80))).unwrap_err();
        assert_eq!(
            err,
            ProtocolError::AmountTooLong {
                field: "amount",
                digits: 80
            }
        );
        // The boundary itself is accepted.
        assert!(ChainEvent::try_from(detected("0xabc", &"9".repeat(78))).is_ok());
    }

    #[test]
    fn malformed_amounts_are_named_errors() {
        for (s, want) in [
            ("", ProtocolError::AmountEmpty { field: "amount" }),
            ("-1", ProtocolError::AmountNotDigits { field: "amount" }),
            ("1.5", ProtocolError::AmountNotDigits { field: "amount" }),
            ("1e3", ProtocolError::AmountNotDigits { field: "amount" }),
            ("١٢", ProtocolError::AmountNotDigits { field: "amount" }),
        ] {
            assert_eq!(
                ChainEvent::try_from(detected("0xabc", s)).unwrap_err(),
                want,
                "{s:?}"
            );
        }
    }

    #[test]
    fn case_folded_and_mixed_addresses_stay_byte_identical() {
        for addr in ["0xAbCdEf0123", "0xabcdef0123", "0XABCDEF0123"] {
            let ev = ChainEvent::try_from(detected(addr, "5")).unwrap();
            let bytes = v1::ChainEvent::from(ev).encode_to_vec();
            let back =
                ChainEvent::try_from(v1::ChainEvent::decode(bytes.as_slice()).unwrap()).unwrap();
            match back.kind {
                ChainEventKind::PaymentDetected {
                    address, payment, ..
                } => {
                    assert_eq!(address.as_str(), addr);
                    assert_eq!(payment.tx_hash.as_str(), "0xAbC");
                }
                other => panic!("wrong kind {other:?}"),
            }
        }
    }

    #[test]
    fn event_without_payload_or_payment_is_refused() {
        let mut e = detected("a", "1");
        e.event = None;
        assert_eq!(
            ChainEvent::try_from(e).unwrap_err(),
            ProtocolError::EmptyEvent
        );

        let mut e = detected("a", "1");
        if let Some(v1::chain_event::Event::PaymentDetected(p)) = &mut e.event {
            p.payment = None;
        }
        assert_eq!(
            ChainEvent::try_from(e).unwrap_err(),
            ProtocolError::Missing { field: "payment" }
        );
    }

    #[test]
    fn unspecified_adapter_state_is_refused() {
        let e = v1::ChainEvent {
            seq: 1,
            chain_id: "c".into(),
            event: Some(v1::chain_event::Event::AdapterStatus(
                v1::AdapterStatus::default(),
            )),
        };
        assert_eq!(
            ChainEvent::try_from(e).unwrap_err(),
            ProtocolError::UnknownState(0)
        );
    }

    #[test]
    fn whitespace_in_text_is_refused() {
        assert_eq!(
            ChainText::parse("address", " 0xabc").unwrap_err(),
            ProtocolError::TextInvalidChar { field: "address" }
        );
    }

    #[test]
    fn contract_file_is_the_one_compiled() {
        // The file adapters consume must declare the package this crate names.
        let proto = include_str!("../proto/payserver/chain/v1/chain.proto");
        assert!(proto.contains(&format!("package {};", crate::CONTRACT_V1)));
        assert!(!proto.to_lowercase().contains("latepaid"));
    }
}
