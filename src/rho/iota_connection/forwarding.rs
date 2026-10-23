use super::*;

impl IotaConnection {
    pub(super) async fn handle_omega_forward(self: Arc<Self>, cv: CommunicationValue) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let iota_for_closure = self.clone();
        let response_cv = self
            .state
            .omega
            .clone()
            .await_response(&cv.with_sender(self.iota_id), Some(Duration::from_secs(20)))
            .await;
        match response_cv {
            Ok(response_cv) => iota_for_closure.send_message(&response_cv).await,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Omega,
                    "Iota management forwarding failed: {}",
                    error
                );
                self.send_error_response(
                    message_id,
                    CommunicationType::ErrorInternal,
                    Some(&format!("Omega forwarding failed: {error}")),
                )
                .await;
            }
        }
    }

    pub(super) async fn handle_omega_forward_without_sender(
        self: Arc<Self>,
        cv: CommunicationValue,
    ) {
        let Ok(message_id) = cv.require_id() else {
            return;
        };
        let iota_for_closure = self.clone();
        let request = registration_request(&cv, self.iota_id);
        let mut response_cv = self
            .state
            .omega
            .clone()
            .await_response(&request, Some(Duration::from_secs(8)))
            .await;
        if let Err(error) = &response_cv {
            log_err!(
                self.iota_id as i64,
                PrintType::Omega,
                "GetRegister request_id={} failed: {}; retrying once",
                message_id,
                error
            );
            response_cv = self
                .state
                .omega
                .clone()
                .await_response(&request, Some(Duration::from_secs(8)))
                .await;
        }
        match response_cv {
            Ok(response_cv) => iota_for_closure.send_message(&response_cv).await,
            Err(error) => {
                log_err!(
                    self.iota_id as i64,
                    PrintType::Omega,
                    "GetRegister forwarding failed: {}",
                    error
                );
                self.send_error_response(
                    message_id,
                    CommunicationType::ErrorInternal,
                    Some(&format!("Omega forwarding failed: {error}")),
                )
                .await;
            }
        }
    }
}
