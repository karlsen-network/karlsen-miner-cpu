use crate::{
    pow::{self, HeaderHasher},
    proto::{
        karlsend_request::Payload, GetBlockTemplateRequestMessage, GetInfoRequestMessage, KarlsendRequest,
        NotifyBlockAddedRequestMessage, NotifyNewBlockTemplateRequestMessage, RpcBlock, RpcNotifyCommand,
        SubmitBlockRequestMessage,
    },
    Hash,
};

impl KarlsendRequest {
    #[must_use]
    #[inline(always)]
    pub fn get_info_request() -> Self {
        KarlsendRequest { id: 1063, payload: Some(Payload::GetInfoRequest(GetInfoRequestMessage {})) }
    }

    #[must_use]
    #[inline(always)]
    pub fn notify_block_added() -> Self {
        KarlsendRequest {
            id: 1007,
            payload: Some(Payload::NotifyBlockAddedRequest(NotifyBlockAddedRequestMessage {
                command: RpcNotifyCommand::NotifyStart as i32,
            })),
        }
    }

    #[must_use]
    #[inline(always)]
    pub fn submit_block(block: RpcBlock) -> Self {
        KarlsendRequest {
            id: 1003,
            payload: Some(Payload::SubmitBlockRequest(SubmitBlockRequestMessage {
                block: Some(block),
                allow_non_daa_blocks: false,
            })),
        }
    }
}

impl From<GetInfoRequestMessage> for KarlsendRequest {
    #[inline(always)]
    fn from(a: GetInfoRequestMessage) -> Self {
        KarlsendRequest { id: 1063, payload: Some(Payload::GetInfoRequest(a)) }
    }
}

impl From<NotifyBlockAddedRequestMessage> for KarlsendRequest {
    #[inline(always)]
    fn from(a: NotifyBlockAddedRequestMessage) -> Self {
        KarlsendRequest { id: 1007, payload: Some(Payload::NotifyBlockAddedRequest(a)) }
    }
}

impl From<GetBlockTemplateRequestMessage> for KarlsendRequest {
    #[inline(always)]
    fn from(a: GetBlockTemplateRequestMessage) -> Self {
        KarlsendRequest { id: 1005, payload: Some(Payload::GetBlockTemplateRequest(a)) }
    }
}

impl From<NotifyNewBlockTemplateRequestMessage> for KarlsendRequest {
    #[inline(always)]
    fn from(a: NotifyNewBlockTemplateRequestMessage) -> Self {
        KarlsendRequest { id: 1081, payload: Some(Payload::NotifyNewBlockTemplateRequest(a)) }
    }
}

impl RpcBlock {
    #[must_use]
    #[inline(always)]
    pub fn block_hash(&self) -> Option<Hash> {
        let mut hasher = HeaderHasher::new();
        pow::serialize_header(&mut hasher, self.header.as_ref()?, false);
        Some(hasher.finalize())
    }
}
