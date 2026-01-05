use crate::data::communication::{CommunicationType, CommunicationValue, DataTypes};
use crate::omega::omega_connection::OmegaConnection;
use json::number::Number;
use tokio::time::Instant;
use uuid::Uuid;

impl OmegaConnection {
    pub async fn send_ping(&self) {
        let uuid = Uuid::new_v4();
        let send_time = Instant::now();

        self.message_send_times.lock().await.insert(uuid, send_time);
        self.send_ping_message(uuid).await;
    }

    pub async fn send_ping_message(&self, uuid: Uuid) {
        let ping_message = CommunicationValue::new(CommunicationType::ping)
            .with_id(uuid)
            .add_data_num(
                DataTypes::last_ping,
                Number::from(*self.last_ping.lock().await),
            );

        self.send_message(&ping_message).await;
    }

    /// Handles incoming pong and calculates latency
    pub async fn handle_pong(&self, cv: &CommunicationValue, _log: bool) {
        let id = cv.get_id();
        let send_time_opt = {
            let queue = self.message_send_times.lock().await;
            queue.get(&id).cloned()
        };

        if let Some(send_time) = send_time_opt {
            let ping = Instant::now().duration_since(send_time).as_millis() as i64;
            self.message_send_times.lock().await.remove(&id);

            *self.last_ping.lock().await = ping as i64;
        }
    }
}
