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

/// Initialize the logging subsystem.
/// Must be called exactly once during startup.
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

            // Console (ANSI-colored)
            println!("{}", colorize(msg.kind, msg.is_error).paint(&line));

            // File (plain text)
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

/** Internal async logging entry point.
* Not exposed publicly; all access goes through macros.
*/
pub fn log_internal(
    sender: Option<i64>,
    kind: PrintType,
    prefix: &'static str,
    is_error: bool,
    message: String,
) {
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
/// Log a general informational message.
#[macro_export]
macro_rules! log {

    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, "", false, format!($($arg)*))
    };

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, "", false, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            "",
            false,
            format!($($arg)*)
        )
    };
}
/// Log an inbound message (`>`).
#[macro_export]
macro_rules! log_in {
    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, ">", false, format!($($arg)*))
    };

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, ">", false, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            ">",
            false,
            format!($($arg)*)
        )
    };
}
/// Log an outbound message (`<`).
#[macro_export]
macro_rules! log_out {
    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, "<", false, format!($($arg)*))
    };

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, "<", false, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            "<",
            false,
            format!($($arg)*)
        )
    };
}
/// Log an error message (`>>`).
#[macro_export]
macro_rules! log_err {

    // actor only
    ($kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(None, $kind, ">>", true, format!($($arg)*))
    };

    // sender + actor
    ($sender:expr, $kind:expr, $($arg:tt)*) => {
        $crate::util::logger::log_internal(Some($sender), $kind, ">>", true, format!($($arg)*))
    };

    // plain
    ($($arg:tt)*) => {
        $crate::util::logger::log_internal(
            None,
            $crate::util::logger::PrintType::General,
            ">>",
            true,
            format!($($arg)*)
        )
    };
}
