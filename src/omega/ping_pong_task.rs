use epsilon_core::{CommunicationType, CommunicationValue, DataTypes, DataValue, rand_u32};
use std::time::Duration;
use tokio::time::Instant;

use crate::omega::omega_connection::OmegaConnection;

const PING_TIMEOUT: Duration = Duration::from_secs(30);

impl OmegaConnection {
    pub async fn send_ping(&self) {
        let id = rand_u32();
        let send_time = Instant::now();

        let mut message_send_times = self.message_send_times.lock().await;
        message_send_times.retain(|_uuid, time| time.elapsed() < PING_TIMEOUT);
        message_send_times.insert(id as i64, send_time);

        self.send_ping_message(id).await;
    }

    pub async fn send_ping_message(&self, id: u32) {
        let ping_message = CommunicationValue::new(CommunicationType::ping)
            .with_id(id)
            .add_data(
                DataTypes::last_ping,
                DataValue::Number(self.last_ping.lock().await.unwrap()),
            );

        self.send_message(&ping_message).await;
    }

    /// Handles incoming pong and calculates latency
    pub async fn handle_pong(&self, cv: &CommunicationValue, _log: bool) {
        let id = cv.get_id();
        let mut message_send_times = self.message_send_times.lock().await;
        if let Some(send_time) = message_send_times.remove(&(id as i64)) {
            let ping = Instant::now().duration_since(send_time).as_millis() as i64;
            *self.last_ping.lock().await = ping;
        }
    }
}
