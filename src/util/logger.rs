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
use mtp::codec::{CommunicationType, CommunicationValue, DataTypeId, DataValue, TypeMap, Version};

static LOGGER: OnceLock<mpsc::SyncSender<LogMessage>> = OnceLock::new();
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

struct LogMessage {
    timestamp_ms: u128,
    sender: Option<i64>,
    prefix: &'static str,
    kind: PrintType,
    is_error: bool,
    message: String,
}

pub fn startup(queue_capacity: usize) {
    let (tx, rx) = mpsc::sync_channel::<LogMessage>(queue_capacity);
    LOGGER.set(tx).expect("Logger already initialized");

    thread::spawn(move || {
        let log_dir = crate::WORKING_DIR.join("logs");
        fs::create_dir_all(&log_dir).expect("Failed to create log directory");
        prune_logs(&log_dir);

        let start_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut sequence = 0;
        let path = log_path(&log_dir, start_ts, sequence);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file");

        let mut last_drop_report = Instant::now();
        loop {
            match rx.recv_timeout(DROPPED_LOG_REPORT_INTERVAL) {
                Ok(msg) => write_message(&mut file, msg),
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    report_dropped_logs(&mut file);
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
    match OpenOptions::new().create(true).append(true).open(log_path(
        log_dir,
        start_ts,
        next_sequence,
    )) {
        Ok(next_file) => {
            *file = next_file;
            *sequence = next_sequence;
            prune_logs(log_dir);
        }
        Err(error) => eprintln!("Failed to rotate Omikron log file: {error}"),
    }
}

fn prune_logs(log_dir: &Path) {
    let Ok(entries) = fs::read_dir(log_dir) else {
        return;
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
    let ts = fixed_box(&msg.timestamp_ms.to_string(), 13);
    let sender = match msg.sender {
        Some(id) => fixed_box(&id.to_string(), 19),
        _ => fixed_box("", 19),
    };
    let line = format!("{} {} {} {}", ts, sender, msg.prefix, msg.message);

    println!("{}", colorize(msg.kind, msg.is_error).paint(&line));
    if let Err(error) = writeln!(file, "{}", line) {
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
                is_error: true,
                message: format!(
                    "Dropped {dropped} log messages because the logger queue was full"
                ),
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

fn fixed_box(content: &str, width: usize) -> String {
    let s: String = content.chars().take(width).collect();
    let len = s.chars().count();
    if len < width {
        format!("[{}{}]", " ".repeat(width - len), s)
    } else {
        s
    }
}

pub fn log_internal(
    sender: i64,
    kind: PrintType,
    prefix: &'static str,
    is_error: bool,
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
            is_error,
            message,
        };
        match tx.try_send(message) {
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

    log_internal(
        cv.sender()
            .and_then(|sender| i64::try_from(sender).ok())
            .unwrap_or(0),
        print_type.unwrap_or(PrintType::General),
        prefix,
        false,
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

    let data = cv.data().unwrap_or(&[]);

    let formated_data = format_data_container(
        data.iter().map(|(k, v)| (*k, v.clone())).collect(),
        Version(3, 0),
    );

    parts.push(format!("{}", formated_data));

    parts.join(": ")
}

fn format_data_container(data: Vec<(DataTypeId, DataValue)>, version: Version) -> String {
    let parts: Vec<String> = data
        .into_iter()
        .map(|(key, value)| {
            let key_str = key.to_string();

            if is_secret_data_type(key) {
                return format!("{}=<redacted>", key_str);
            }

            match value {
                DataValue::Str(s) => format!("{}=\"{}\"", key_str, abbreviate_string(&s)),

                DataValue::Container(inner) => {
                    let inner_formatted = format_data_container(inner, version.clone());
                    format!("{}={{ {} }}", key_str, inner_formatted)
                }

                DataValue::Array(arr) => {
                    let arr_formatted = format_array(arr, version.clone());
                    format!("{}=[{}]", key_str, arr_formatted)
                }

                DataValue::Bool(b) => format!("{}={}", key_str, b),

                DataValue::BoolTrue => format!("{}=true", key_str),
                DataValue::BoolFalse => format!("{}=false", key_str),

                DataValue::SignedNumber(num) => format!("{}={}", key_str, num),
                DataValue::UnsignedNumber(num) => format!("{}={}", key_str, num),
                DataValue::Bytes(bytes) => format!("{}=<{} bytes>", key_str, bytes.len()),

                _ => "".to_string(),
            }
        })
        .collect();

    parts.join(", ")
}

fn is_secret_data_type(key: DataTypeId) -> bool {
    matches!(
        TypeMap::latest().data_type_name(key.0),
        Some("InvitationToken" | "InvitationPassword" | "ResetToken" | "RegisterId" | "NewToken")
    )
}

fn format_array(arr: Vec<DataValue>, version: Version) -> String {
    let parts: Vec<String> = arr
        .into_iter()
        .map(|value| match value {
            DataValue::Str(s) => format!("\"{}\"", abbreviate_string(&s)),

            DataValue::Container(inner) => {
                let inner_formatted = format_data_container(inner, version.clone());
                format!("{{ {} }}", inner_formatted)
            }

            DataValue::Array(inner_arr) => {
                let formatted = format_array(inner_arr, version.clone());
                format!("[{}]", formatted)
            }

            DataValue::Bool(b) => b.to_string(),

            DataValue::BoolTrue => "true".to_string(),
            DataValue::BoolFalse => "false".to_string(),

            DataValue::SignedNumber(num) => num.to_string(),
            DataValue::UnsignedNumber(num) => num.to_string(),
            DataValue::Bytes(bytes) => format!("<{} bytes>", bytes.len()),

            _ => String::new(),
        })
        .collect();

    parts.join(", ")
}

fn abbreviate_string(value: &str) -> String {
    const EDGE_LENGTH: usize = 4;

    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= EDGE_LENGTH * 2 {
        return value.to_string();
    }

    let prefix: String = chars.iter().take(EDGE_LENGTH).collect();
    let suffix: String = chars.iter().rev().take(EDGE_LENGTH).rev().collect();
    format!("{prefix}...{suffix}")
}

#[cfg(test)]
mod tests {
    use super::{abbreviate_string, format_cv};
    use mtp::codec::{CommunicationType, CommunicationValue, DataType, DataValue, TypeMap};

    #[test]
    fn abbreviates_only_strings_longer_than_eight_characters() {
        assert_eq!(abbreviate_string("12345678"), "12345678");
        assert_eq!(abbreviate_string("123456789"), "1234...6789");
        assert_eq!(abbreviate_string("YWJjZGVmZ2hpag=="), "YWJj...ag==");
    }

    #[test]
    fn redacts_invitation_and_account_credentials() {
        let reset_token = DataType::ResetToken.try_to_id(&TypeMap::latest()).unwrap();
        let value = CommunicationValue::new(CommunicationType::RedeemUserInvitation)
            .add_typed_default(DataType::InvitationToken, DataValue::Str("short123".into()))
            .add_typed_default(
                DataType::Invitations,
                DataValue::Array(vec![DataValue::Container(vec![(
                    reset_token,
                    DataValue::Str("reset-secret".into()),
                )])]),
            );
        let formatted = format_cv(&value);
        assert!(!formatted.contains("short123"));
        assert!(!formatted.contains("reset-secret"));
        assert_eq!(formatted.matches("<redacted>").count(), 2);
    }
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
