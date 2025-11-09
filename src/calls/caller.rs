use tokio::sync::mpsc::UnboundedSender;
use tungstenite::Utf8Bytes;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Caller {
    pub user_id: Uuid,
    pub tx: UnboundedSender<Utf8Bytes>,
}
impl Caller {
    pub fn send(&self, msg: impl Into<Utf8Bytes>) {
        let _ = self.tx.send(msg.into());
    }
}
