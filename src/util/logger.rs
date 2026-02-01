use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    sync::{OnceLock, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};

use ansi_term::Color;

static LOGGER: OnceLock<mpsc::Sender<LogMessage>> = OnceLock::new();

#[derive(Clone, Copy)]
pub enum PrintType {
    Call,
    Client,
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

pub fn startup() {
    let (tx, rx) = mpsc::channel::<LogMessage>();
    LOGGER.set(tx).expect("Logger already initialized");

    thread::spawn(move || {
        let log_dir = Path::new("logs");
        fs::create_dir_all(log_dir).expect("Failed to create log directory");

        let start_ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let path = log_dir.join(format!("log_{}.txt", start_ts));
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file");

        for msg in rx {
            let ts = fixed_box(&msg.timestamp_ms.to_string(), 13);
            let sender = match msg.sender {
                Some(id) => fixed_box(&id.to_string(), 19),
                _ => fixed_box("", 19),
            };

            let line = format!("{} {} {} {}", ts, sender, msg.prefix, msg.message);

            println!("{}", colorize(msg.kind, msg.is_error).paint(&line));

            let _ = writeln!(file, "{}", line);
        }
    });
}

fn colorize(kind: PrintType, is_error: bool) -> Color {
    if is_error {
        return Color::Red;
    }

    match kind {
        PrintType::Call => Color::Purple,
        PrintType::Client => Color::Green,
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
        let _ = tx.send(LogMessage {
            timestamp_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
            sender,
            prefix,
            kind,
            is_error,
            message,
        });
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
