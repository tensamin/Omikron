use ansi_term::Color;

pub fn print_start_message() {
    println!("{}", Color::Yellow.paint("> Iota inbound"));
    println!("{}", Color::Purple.paint("< Iota outbound"));
    println!("{}", Color::Green.paint("> Client inbound"));
    println!("{}", Color::Blue.paint("> Client outbound"));
    println!("{}", Color::Cyan.paint("> Omega inbound"));
    println!("{}", Color::Cyan.paint("< Omega outbound"));
    println!("{}", Color::White.paint("General info"));
    println!("{}", Color::White.paint(">> Erros"));
}
pub enum PrintType {
    IotaIn,
    IotaOut,
    OmegaIn,
    OmegaOut,
    ClientIn,
    ClientOut,
    General,
}
pub fn line(key: PrintType, message: &str) {
    match key {
        PrintType::IotaIn => println!(
            "{}{}",
            Color::Yellow.paint(">"),
            Color::Yellow.paint(message)
        ),
        PrintType::IotaOut => println!(
            "{}{}",
            Color::Purple.paint("<"),
            Color::Purple.paint(message)
        ),
        PrintType::OmegaIn => println!("{}{}", Color::Cyan.paint(">"), Color::Cyan.paint(message)),
        PrintType::OmegaOut => println!("{}{}", Color::Cyan.paint("<"), Color::Cyan.paint(message)),
        PrintType::ClientIn => {
            println!("{}{}", Color::Green.paint(">"), Color::Green.paint(message))
        }
        PrintType::ClientOut => {
            println!("{}{}", Color::Blue.paint("<"), Color::Blue.paint(message))
        }
        PrintType::General => println!("{}", Color::White.paint(message)),
    }
}
pub fn line_err(key: PrintType, message: &str) {
    match key {
        PrintType::IotaIn => println!(
            "{}{}",
            Color::Yellow.paint(">>"),
            Color::Yellow.paint(message)
        ),
        PrintType::IotaOut => println!(
            "{}{}",
            Color::Purple.paint("<<"),
            Color::Purple.paint(message)
        ),
        PrintType::OmegaIn => println!("{}{}", Color::Cyan.paint(">>"), Color::Cyan.paint(message)),
        PrintType::OmegaOut => {
            println!("{}{}", Color::Cyan.paint("<<"), Color::Cyan.paint(message))
        }
        PrintType::ClientIn => println!(
            "{}{}",
            Color::Green.paint(">>"),
            Color::Green.paint(message)
        ),
        PrintType::ClientOut => {
            println!("{}{}", Color::Blue.paint("<<"), Color::Blue.paint(message))
        }
        PrintType::General => println!("{}", Color::Red.paint(message)),
    }
}
