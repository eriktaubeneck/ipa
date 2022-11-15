use crate::{
    helpers::{
        buffers::fsv::FixedSizeByteVec,
        network::{ChannelId, MessageEnvelope},
        MessagePayload, MESSAGE_PAYLOAD_SIZE_BYTES,
    },
    protocol::RecordId,
};
use std::collections::HashMap;
use std::ops::Range;

/// Use the buffer that allocates 8 bytes per element. It could probably go down to 4 if the
/// only thing IPA sends is a single field value. To support arbitrarily sized values, it needs
/// to be at least 16 bytes to be able to store a fat pointer in it.
type ByteBuf = FixedSizeByteVec<{ MESSAGE_PAYLOAD_SIZE_BYTES }>;

/// Buffer that keeps messages that must be sent to other helpers
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct SendBuffer {
    items_in_batch: usize,
    batch_count: usize,
    inner: HashMap<ChannelId, ByteBuf>,
}

#[derive(thiserror::Error, Debug)]
pub enum PushError {
    #[error("Record {record_id:?} is out of accepted range {accepted_range:?}")]
    OutOfRange {
        channel_id: ChannelId,
        record_id: RecordId,
        accepted_range: Range<RecordId>,
    },
    #[error(
        "Message with the same record id {record_id:?} has been already sent to {channel_id:?}"
    )]
    Duplicate {
        channel_id: ChannelId,
        record_id: RecordId,
        previous_value: MessagePayload,
    },
}

/// Send buffer configuration is defined over two parameters. `items_in_batch` indicates how many
/// elements a single request to send data to network layer can hold. The size of the batch in
/// bytes is defined as `items_in_batch` * `ByteBuf::ELEMENT_SIZE_BYTES`.
///
/// `batch_count` defines the overall capacity of the send buffer as `items_in_batch` * `batch_count`.
/// Setting it to `2` will double the capacity of the send buffer as at most two batches can be kept
/// in memory, `4` quadruples the capacity etc.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    pub items_in_batch: u32,
    pub batch_count: u32,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            items_in_batch: 1,
            batch_count: 1,
        }
    }
}

impl SendBuffer {
    pub fn new(config: Config) -> Self {
        Self {
            items_in_batch: config.items_in_batch as usize,
            batch_count: config.batch_count as usize,
            inner: HashMap::default(),
        }
    }

    pub fn push(
        &mut self,
        channel_id: &ChannelId,
        msg: &MessageEnvelope,
    ) -> Result<Option<Vec<u8>>, PushError> {
        assert!(
            msg.payload.len() <= ByteBuf::ELEMENT_SIZE_BYTES,
            "Message payload exceeds the maximum allowed size"
        );

        let buf = if let Some(buf) = self.inner.get_mut(channel_id) {
            buf
        } else {
            self.inner
                .entry(channel_id.clone())
                .or_insert_with(|| FixedSizeByteVec::new(self.batch_count, self.items_in_batch))
        };

        // Make sure record id is within the accepted range and reject the request if it is not
        let start = RecordId::from(u32::try_from(buf.elements_drained()).unwrap());
        let end = RecordId::from(u32::try_from(buf.elements_drained() + buf.capacity()).unwrap());

        if !(start..end).contains(&msg.record_id) {
            return Err(PushError::OutOfRange {
                channel_id: channel_id.clone(),
                record_id: msg.record_id,
                accepted_range: (start..end),
            });
        }

        // Determine the offset for this record and insert the payload inside the buffer.
        // Message payload may be less than allocated capacity per element, if that's the case
        // payload will be extended to fill the gap.
        let index: u32 = u32::from(msg.record_id) - u32::from(start);
        let mut payload = [0; ByteBuf::ELEMENT_SIZE_BYTES];
        payload[..msg.payload.len()].copy_from_slice(&msg.payload);
        if let Some(v) = buf.insert(index as usize, payload) {
            return Err(PushError::Duplicate {
                record_id: msg.record_id,
                channel_id: channel_id.clone(),
                previous_value: v.try_into().unwrap(),
            });
        }

        Ok(buf.take())
    }
}

impl Config {
    #[must_use]
    pub fn batch_count(self, batch_count: u32) -> Self {
        Self {
            items_in_batch: self.items_in_batch,
            batch_count,
        }
    }

    #[must_use]
    pub fn items_in_batch(self, items_in_batch: u32) -> Self {
        Self {
            items_in_batch,
            batch_count: self.batch_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::helpers::buffers::send::{ByteBuf, Config, PushError};
    use crate::helpers::buffers::SendBuffer;
    use crate::helpers::Role;
    use crate::protocol::{RecordId, Step};

    use tinyvec::array_vec;

    use crate::helpers::network::{ChannelId, MessageEnvelope};

    impl Clone for MessageEnvelope {
        fn clone(&self) -> Self {
            MessageEnvelope {
                record_id: self.record_id,
                // tinyvec implements copy for small arrays
                payload: self.payload,
            }
        }
    }

    #[test]
    fn rejects_records_out_of_range() {
        let record_id = RecordId::from(11_u32);
        let mut buf = SendBuffer::new(Config::default());
        let msg = empty_msg(record_id);

        assert!(matches!(
            buf.push(&ChannelId::new(Role::H1, Step::default()), &msg),
            Err(PushError::OutOfRange { .. }),
        ));
    }

    #[test]
    fn does_not_corrupt_messages() {
        let c1 = ChannelId::new(Role::H1, Step::default());
        let mut buf = SendBuffer::new(Config::default().items_in_batch(10));

        let batch = (0u8..10)
            .find_map(|i| {
                let msg = MessageEnvelope {
                    record_id: RecordId::from(u32::from(i)),
                    payload: array_vec!([u8; ByteBuf::ELEMENT_SIZE_BYTES] => i),
                };
                buf.push(&c1, &msg).ok().flatten()
            })
            .unwrap();

        for (i, v) in batch.chunks(ByteBuf::ELEMENT_SIZE_BYTES).enumerate() {
            let payload = u64::from_le_bytes(v.try_into().unwrap());
            assert!(payload < u64::from(u8::MAX));

            assert_eq!(usize::from(u8::try_from(payload).unwrap()), i);
        }
    }

    #[test]
    fn offset_is_per_channel() {
        let mut buf = SendBuffer::new(Config::default());
        let c1 = ChannelId::new(Role::H1, Step::default());
        let c2 = ChannelId::new(Role::H2, Step::default());

        let m1 = empty_msg(0);
        let m2 = empty_msg(1);

        buf.push(&c1, &m1).unwrap();
        buf.push(&c1, &m2).unwrap();

        assert!(matches!(
            buf.push(&c2, &m2),
            Err(PushError::OutOfRange { .. }),
        ));
    }

    #[test]
    fn rejects_duplicates() {
        let mut buf = SendBuffer::new(Config::default().items_in_batch(10));
        let channel = ChannelId::new(Role::H1, Step::default());
        let record_id = RecordId::from(3_u32);
        let m1 = empty_msg(record_id);
        let m2 = empty_msg(record_id);

        assert!(matches!(buf.push(&channel, &m1), Ok(None)));
        assert!(matches!(
            buf.push(&channel, &m2),
            Err(PushError::Duplicate { .. })
        ));
    }

    #[test]
    fn accepts_records_within_the_valid_range() {
        let mut buf = SendBuffer::new(Config::default().items_in_batch(10));
        let msg = empty_msg(5);

        assert!(matches!(
            buf.push(&ChannelId::new(Role::H1, Step::default()), &msg),
            Ok(None)
        ));
    }

    #[test]
    fn accepts_records_from_next_range_after_flushing() {
        let mut buf = SendBuffer::new(Config::default());
        let channel = ChannelId::new(Role::H1, Step::default());
        let next_msg = empty_msg(1);
        let this_msg = empty_msg(0);

        // this_msg belongs to current range, should be accepted
        assert!(matches!(buf.push(&channel, &this_msg), Ok(Some(_))));
        // this_msg belongs to next valid range that must be set as current by now
        assert!(matches!(buf.push(&channel, &next_msg), Ok(Some(_))));
    }

    fn empty_msg<I: TryInto<u32>>(record_id: I) -> MessageEnvelope
    where
        I::Error: std::fmt::Debug,
    {
        MessageEnvelope {
            record_id: RecordId::from(record_id.try_into().unwrap()),
            payload: array_vec!(),
        }
    }
}
