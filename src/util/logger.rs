use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering},
        mpsc::{self, RecvTimeoutError, TrySendError},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use ansi_term::Color;
use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataTypeId, DataValue, TypeMap};

static LOGGER: OnceLock<mpsc::SyncSender<LoggerCommand>> = OnceLock::new();
static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);
const DROPPED_LOG_REPORT_INTERVAL: Duration = Duration::from_secs(5);
const MAX_LOG_FILE_BYTES: u64 = 16 * 1024 * 1024;
const RETAINED_LOG_FILES: usize = 8;

#[allow(dead_code)]
#[derive(Clone, Copy)]
pub enum PrintType {
    Call,
    Client,
    App,
    Iota,
    Omikron,
    Omega,
    General,
}
impl PrintType {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Call => "call",
            Self::Client => "client",
            Self::App => "app",
            Self::Iota => "iota",
            Self::Omikron => "omikron",
            Self::Omega => "omega",
            Self::General => "general",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}
impl LogLevel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

enum LoggerCommand {
    Write(LogMessage),
    Shutdown,
}

pub struct LoggerGuard {
    thread: Option<thread::JoinHandle<()>>,
}
impl Drop for LoggerGuard {
    fn drop(&mut self) {
        if let Some(tx) = LOGGER.get() {
            let _ = tx.send(LoggerCommand::Shutdown);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct LogMessage {
    timestamp_ms: u128,
    sender: Option<i64>,
    prefix: &'static str,
    kind: PrintType,
    level: LogLevel,
    event: &'static str,
    message: String,
}

pub fn startup(queue_capacity: usize) -> std::io::Result<LoggerGuard> {
    let log_dir = crate::WORKING_DIR.join("logs");
    fs::create_dir_all(&log_dir)?;
    prune_logs(&log_dir);
    let start_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(log_path(&log_dir, start_ts, 0))?;
    let (tx, rx) = mpsc::sync_channel(queue_capacity.max(1));
    LOGGER.set(tx).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "logger already initialized",
        )
    })?;
    let thread = thread::spawn(move || {
        let mut file = file;
        let mut sequence = 0;
        let mut last_drop_report = Instant::now();
        loop {
            match rx.recv_timeout(DROPPED_LOG_REPORT_INTERVAL) {
                Ok(LoggerCommand::Write(msg)) => write_message(&mut file, msg),
                Ok(LoggerCommand::Shutdown) => {
                    report_dropped_logs(&mut file);
                    if let Err(error) = file.flush() {
                        eprintln!("Failed to flush Omikron log file: {error}");
                    }
                    break;
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    report_dropped_logs(&mut file);
                    let _ = file.flush();
                    break;
                }
            }

            if last_drop_report.elapsed() >= DROPPED_LOG_REPORT_INTERVAL {
                report_dropped_logs(&mut file);
                last_drop_report = Instant::now();
            }
            rotate_log_if_needed(&mut file, &log_dir, start_ts, &mut sequence);
        }
    });
    Ok(LoggerGuard {
        thread: Some(thread),
    })
}

fn log_path(log_dir: &Path, start_ts: u64, sequence: u32) -> PathBuf {
    log_dir.join(format!("log_{start_ts}_{sequence}.txt"))
}

fn rotate_log_if_needed(
    file: &mut std::fs::File,
    log_dir: &Path,
    start_ts: u64,
    sequence: &mut u32,
) {
    if !file
        .metadata()
        .is_ok_and(|metadata| metadata.len() >= MAX_LOG_FILE_BYTES)
    {
        return;
    }
    let next_sequence = sequence.saturating_add(1);
    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(log_path(log_dir, start_ts, next_sequence)) {
        Ok(next_file) => {
            *file = next_file;
            *sequence = next_sequence;
            prune_logs(log_dir);
        }
        Err(error) => eprintln!("Failed to rotate Omikron log file: {error}"),
    }
}

fn prune_logs(log_dir: &Path) {
    let entries = match fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!(
                "Unable to enumerate log directory {}: {error}",
                log_dir.display()
            );
            return;
        }
    };
    let mut logs = entries
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with("log_") && name.ends_with(".txt"))
        })
        .collect::<Vec<_>>();
    logs.sort_by_key(|entry| {
        entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .unwrap_or(UNIX_EPOCH)
    });
    let remove_count = logs.len().saturating_sub(RETAINED_LOG_FILES);
    for entry in logs.into_iter().take(remove_count) {
        if let Err(error) = fs::remove_file(entry.path()) {
            eprintln!("Failed to remove old Omikron log file: {error}");
        }
    }
}

fn write_message(file: &mut std::fs::File, msg: LogMessage) {
    let sender = msg
        .sender
        .map(|id| id.to_string())
        .unwrap_or_else(|| "-".into());
    let direction = match msg.prefix.trim() {
        ">" => "in",
        "<" => "out",
        ">>" => "internal",
        _ => "local",
    };
    let line = format!(
        "{} level={} component={} direction={} sender={} event={} message={:?}",
        msg.timestamp_ms,
        msg.level.as_str(),
        msg.kind.as_str(),
        direction,
        sender,
        msg.event,
        msg.message
    );
    println!(
        "{}",
        colorize(msg.kind, msg.level == LogLevel::Error).paint(&line)
    );
    if let Err(error) = writeln!(file, "{line}") {
        eprintln!("Failed to write Omikron log file: {error}");
    }
}

fn report_dropped_logs(file: &mut std::fs::File) {
    let dropped = DROPPED_LOGS.swap(0, Ordering::Relaxed);
    if dropped > 0 {
        write_message(
            file,
            LogMessage {
                timestamp_ms: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis(),
                sender: None,
                prefix: ">>",
                kind: PrintType::General,
                level: LogLevel::Error,
                event: "logger.dropped",
                message: format!("count={dropped}"),
            },
        );
    }
}

fn colorize(kind: PrintType, is_error: bool) -> Color {
    if is_error {
        return Color::Red;
    }

    match kind {
        PrintType::Call => Color::Purple,
        PrintType::Client => Color::Green,
        PrintType::App => Color::Green,
        PrintType::Iota => Color::Yellow,
        PrintType::Omikron => Color::Blue,
        PrintType::Omega => Color::Cyan,
        PrintType::General => Color::White,
    }
}

pub fn log_internal(
    sender: i64,
    kind: PrintType,
    prefix: &'static str,
    is_error: bool,
    message: String,
) {
    log_event_internal(
        sender,
        kind,
        prefix,
        if is_error {
            LogLevel::Error
        } else {
            LogLevel::Info
        },
        "message",
        message,
    );
}

pub fn log_event_internal(
    sender: i64,
    kind: PrintType,
    prefix: &'static str,
    level: LogLevel,
    event: &'static str,
    message: String,
) {
    let sender = if sender == 0 { None } else { Some(sender) };

    if let Some(tx) = LOGGER.get() {
        let message = LogMessage {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis(),
            sender,
            prefix,
            kind,
            level,
            event,
            message,
        };
        match tx.try_send(LoggerCommand::Write(message)) {
            Ok(()) => {}
            Err(TrySendError::Full(_)) => {
                DROPPED_LOGS.fetch_add(1, Ordering::Relaxed);
            }
            Err(TrySendError::Disconnected(_)) => {
                eprintln!("Omikron logger thread has stopped");
            }
        }
    }
}
#[macro_export]
macro_rules! log_event {
    ($sender:expr, $kind:expr, $level:expr, $event:expr, $($arg:tt)*) => {
        $crate::util::logger::log_event_internal($sender, $kind, "", $level, $event, format!($($arg)*))
    };
}
#[macro_export]
macro_rules! log {
    ($sender: expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal($sender, $kind, "", false, format!($($arg)*))
    };
}
#[macro_export]
macro_rules! log_in {
    ($sender: expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal($sender, $kind, ">", false, format!($($arg)*))
    };
}
#[macro_export]
macro_rules! log_out {
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal($sender, $kind, "<", false, format!($($arg)*))
    };
}
#[macro_export]
macro_rules! log_err {
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal($sender, $kind, ">>", true, format!($($arg)*))
    };
}

// ******** COMMUNICATION VALUES ********
pub fn log_cv_internal(
    prefix: &'static str,
    cv: &CommunicationValue,
    print_type: Option<PrintType>,
) {
    let formatted = format_cv(cv);

    log_event_internal(
        cv.sender()
            .and_then(|sender| i64::try_from(sender).ok())
            .unwrap_or(0),
        print_type.unwrap_or(PrintType::General),
        prefix,
        LogLevel::Debug,
        if prefix.trim() == "<" {
            "protocol.sent"
        } else {
            "protocol.received"
        },
        formatted,
    );
}

pub fn format_cv(cv: &CommunicationValue) -> String {
    let mut parts = Vec::new();

    let sender = cv.sender();
    let receiver = cv.receiver();

    if let (Some(sender), Some(receiver)) = (sender, receiver) {
        parts.push(format!("{} > {}", sender, receiver));
    } else if let Some(sender) = sender {
        parts.push(format!("{}", sender));
    } else if let Some(receiver) = receiver {
        parts.push(format!("> {}", receiver));
    }

    let comm_type = cv
        .get_comm_type_enum()
        .map(|kind| kind.to_string())
        .unwrap_or_else(|| cv.get_type().to_string());
    parts.push(format!("{} (id={:?})", comm_type, cv.id()));

    if cv.is_type(CommunicationType::Relay) {
        parts.push("<opaque relay payload>".to_string());
        return parts.join(": ");
    }

    if has_sensitive_payload(cv) {
        parts.push("<sensitive payload omitted>".to_string());
        return parts.join(": ");
    }

    if let Some(data) = cv.data() {
        let type_map = cv.type_map().cloned().unwrap_or_else(TypeMap::latest);
        parts.push(format_data_container(data, &type_map));
    }

    parts.join(": ")
}

fn has_sensitive_payload(cv: &CommunicationValue) -> bool {
    cv.get_data(DataType::CallPayload).is_some()
        || matches!(
            cv.get_comm_type_enum(),
            Some(
                CommunicationType::PasswordEnrollmentStart
                    | CommunicationType::PasswordEnrollmentResponse
                    | CommunicationType::PasswordEnrollmentFinish
                    | CommunicationType::PasswordProvisioningStart
                    | CommunicationType::PasswordProvisioningResponse
                    | CommunicationType::PasswordProvisioningFinish
                    | CommunicationType::ProvisioningCredential
                    | CommunicationType::CallSetAnonymousJoining
            )
        )
}

fn format_data_container(data: &[(DataTypeId, DataValue)], type_map: &TypeMap) -> String {
    data.iter()
        .map(|(key, value)| {
            let name = type_map
                .data_type_name(key.0)
                .map(str::to_owned)
                .unwrap_or_else(|| key.to_string());
            match value {
                DataValue::SignedNumber(value)
                    if matches!(
                        name.as_str(),
                        "UserId"
                            | "IotaId"
                            | "OmikronId"
                            | "InvitationId"
                            | "RelayMessageId"
                            | "VersionNumber"
                            | "Offset"
                            | "Amount"
                    ) =>
                {
                    format!("{name}={value}")
                }
                DataValue::UnsignedNumber(value)
                    if matches!(
                        name.as_str(),
                        "UserId"
                            | "IotaId"
                            | "OmikronId"
                            | "InvitationId"
                            | "RelayMessageId"
                            | "VersionNumber"
                            | "Offset"
                            | "Amount"
                    ) =>
                {
                    format!("{name}={value}")
                }
                DataValue::Container(inner) => {
                    format!("{name}={{ {} }}", format_data_container(inner, type_map))
                }
                DataValue::Array(values) => format!("{name}=<array:{}>", values.len()),
                DataValue::Str(_) => format!("{name}=<string>"),
                DataValue::Bytes(_) => format!("{name}=<bytes>"),
                DataValue::Bool(_) | DataValue::BoolTrue | DataValue::BoolFalse => {
                    format!("{name}=<bool>")
                }
                DataValue::SignedNumber(_) | DataValue::UnsignedNumber(_) => {
                    format!("{name}=<number>")
                }
                _ => format!("{name}=<value>"),
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

#[macro_export]
macro_rules! log_cv {
    ($kind:expr, $cv:expr) => {
        $crate::util::logger::log_cv_internal("", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::util::logger::log_cv_internal("", &$cv, None)
    };
}

#[macro_export]
macro_rules! log_cv_in {
    ($kind:expr, $cv:expr) => {
        $crate::util::logger::log_cv_internal("> ", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::util::logger::log_cv_internal("> ", &$cv, None)
    };
}
#[macro_export]
macro_rules! log_cv_out {
    ($kind:expr, $cv:expr) => {
        $crate::util::logger::log_cv_internal("< ", &$cv, Some($kind))
    };
    ($cv:expr) => {
        $crate::util::logger::log_cv_internal("< ", &$cv, None)
    };
}

#[cfg(test)]
mod tests {
    use super::{LogLevel, LogMessage, PrintType, format_cv, write_message};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue};

    #[test]
    fn password_payload_is_redacted() {
        let frame = CommunicationValue::new(CommunicationType::PasswordProvisioningStart)
            .with_id(42)
            .add_typed_default(DataType::OpaqueMessage, DataValue::Bytes(vec![0xde, 0xad]));
        let formatted = format_cv(&frame);
        assert!(formatted.contains("PasswordProvisioningStart"));
        assert!(formatted.contains("<sensitive payload omitted>"));
        assert!(!formatted.contains("OpaqueMessage"));
    }

    #[test]
    fn provisioning_credential_is_redacted() {
        let frame = CommunicationValue::new(CommunicationType::ProvisioningCredential)
            .with_id(9)
            .add_typed_default(
                DataType::EncryptedCredential,
                DataValue::Bytes(vec![1, 2, 3, 4]),
            );
        assert!(format_cv(&frame).contains("<sensitive payload omitted>"));
    }

    #[test]
    fn protocol_values_are_metadata_only() {
        let value = CommunicationValue::new(CommunicationType::Success)
            .add_typed_default(
                DataType::SessionToken,
                DataValue::Str("session-secret-value".into()),
            )
            .add_typed_default(
                DataType::CallToken,
                DataValue::Str("livekit-secret-token".into()),
            )
            .add_typed_default(DataType::Username, DataValue::Str("alice".into()))
            .add_typed_default(DataType::UserId, DataValue::SignedNumber(172));
        let formatted = format_cv(&value);
        for secret in ["session-secret-value", "livekit-secret-token", "alice"] {
            assert!(!formatted.contains(secret));
        }
        assert!(formatted.contains("SessionToken=<string>"));
        assert!(formatted.contains("UserId=172"));
        assert!(
            format_cv(&CommunicationValue::new(CommunicationType::Relay))
                .contains("<opaque relay payload>")
        );
    }

    #[test]
    fn persisted_message_has_level_component_and_one_line() {
        let path = std::env::temp_dir().join(format!("omikron-logger-{}", uuid::Uuid::new_v4()));
        let mut file = std::fs::File::create(&path).unwrap();
        write_message(
            &mut file,
            LogMessage {
                timestamp_ms: 123,
                sender: None,
                prefix: "",
                kind: PrintType::Call,
                level: LogLevel::Warn,
                event: "call.failed",
                message: "first\nsecond".into(),
            },
        );
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(contents.lines().count(), 1);
        assert!(contents.contains("level=WARN component=call"));
        assert!(contents.contains("event=call.failed"));
        assert!(contents.contains("first\\nsecond"));
    }
}
