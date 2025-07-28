use synth::AdvancedOsintScanner;
use synth::cli::Args;
use clap::Parser;
use env_logger::Env;

fn display_banner() {
    // Clear screen and display professional banner
    print!("\x1b[2J\x1b[H"); // Clear screen and move cursor to top
    
    // Get system info
    let hostname = std::env::var("HOSTNAME").or_else(|_| std::env::var("COMPUTERNAME")).unwrap_or_else(|_| "unknown".to_string());
    let user = std::env::var("USER").or_else(|_| std::env::var("USERNAME")).unwrap_or_else(|_| "unknown".to_string());
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    
    println!();
    
    // Main SYNTH banner with cyberpunk aesthetic
    println!("       \x1b[38;5;196m███████╗\x1b[38;5;208m██╗   ██╗\x1b[38;5;226m███╗   ██╗\x1b[38;5;46m████████╗\x1b[38;5;51m██╗  ██╗\x1b[0m");
    println!("       \x1b[38;5;196m██╔════╝\x1b[38;5;208m╚██╗ ██╔╝\x1b[38;5;226m████╗  ██║\x1b[38;5;46m╚══██╔══╝\x1b[38;5;51m██║  ██║\x1b[0m");
    println!("       \x1b[38;5;196m███████╗\x1b[38;5;208m ╚████╔╝ \x1b[38;5;226m██╔██╗ ██║\x1b[38;5;46m   ██║   \x1b[38;5;51m███████║\x1b[0m");
    println!("       \x1b[38;5;196m╚════██║\x1b[38;5;208m  ╚██╔╝  \x1b[38;5;226m██║╚██╗██║\x1b[38;5;46m   ██║   \x1b[38;5;51m██╔══██║\x1b[0m");
    println!("       \x1b[38;5;196m███████║\x1b[38;5;208m   ██║   \x1b[38;5;226m██║ ╚████║\x1b[38;5;46m   ██║   \x1b[38;5;51m██║  ██║\x1b[0m");
    println!("       \x1b[38;5;196m╚══════╝\x1b[38;5;208m   ╚═╝   \x1b[38;5;226m╚═╝  ╚═══╝\x1b[38;5;46m   ╚═╝   \x1b[38;5;51m╚═╝  ╚═╝\x1b[0m");
    
    println!();
    println!("              \x1b[3;38;5;147m\"Search what you can't find\"\x1b[0m");
    println!();
    
    // System information sidebar with perfect alignment
    println!("    \x1b[38;5;240m┌─ SYSTEM INFO ─────────────────────────────────────┐\x1b[0m");
    
    // Box inner width is 49 characters (51 total - 2 for borders)
    // Format: "│ ◉ Label      Value" + padding + "│"
    // "│ ◉ " = 4 chars, "      " = 6 chars, so we have 39 chars for value+padding
    
    let format_line = |label: &str, value: &str| {
        let prefix = format!(" ◉ {}", label);
        let spaces_after_label = 6; // Fixed spacing after label
        let used_chars = prefix.len() + spaces_after_label + value.len();
        let padding_needed = 56 - used_chars; // 49 is inner box width
        format!("               \x1b[38;5;240m{}\x1b[0m{}\x1b[38;5;145m{}\x1b[0m{}\x1b[38;5;240m\x1b[0m     ", 
                prefix, " ".repeat(spaces_after_label), value, " ".repeat(padding_needed))
    };
    
    println!("{}", format_line("User", &user));
    println!("{}", format_line("Host", &hostname));
    println!("{}", format_line("Platform", &format!("{}/{}", os, arch)));
    println!("{}", format_line("Version", "v2.1.3-advanced"));
    
    println!("    \x1b[38;5;240m└───────────────────────────────────────────────────┘\x1b[0m");
    println!();
    
    // Animated status line
    print!("    \x1b[38;5;33m▶\x1b[0m \x1b[1;37mInitializing OSINT framework\x1b[0m");
    for i in 0..4 {
        std::thread::sleep(std::time::Duration::from_millis(150));
        match i {
            0 => print!(" \x1b[38;5;196m●\x1b[38;5;240m●●\x1b[0m"),
            1 => print!("\x1b[1K\r    \x1b[38;5;33m▶\x1b[0m \x1b[1;37mInitializing OSINT framework\x1b[0m \x1b[38;5;208m●●\x1b[38;5;240m●\x1b[0m"),
            2 => print!("\x1b[1K\r    \x1b[38;5;33m▶\x1b[0m \x1b[1;37mInitializing OSINT framework\x1b[0m \x1b[38;5;46m●●●\x1b[0m"),
            _ => print!("\x1b[1K\r    \x1b[38;5;33m▶\x1b[0m \x1b[1;37mInitializing OSINT framework\x1b[0m \x1b[38;5;51m✓✓✓\x1b[0m"),
        }
        use std::io::{self, Write};
        io::stdout().flush().unwrap();
    }
    println!(" \x1b[1;32mREADY\x1b[0m");
    println!();
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Display the awesome banner first
    display_banner();
    
    let args = Args::parse();

    // Initialize logging based on verbosity and quiet flags
    let log_level = if args.quiet {
        "error"  // Only show critical errors when quiet
    } else if args.verbose {
        "debug"  // Show all debug info when verbose
    } else {
        "info"   // Default info level
    };

    env_logger::Builder::from_env(Env::default().default_filter_or(log_level))
        .format_timestamp_millis()
        .init();

    log::info!("Synth starting with args: {:?}", args);

    let scanner = AdvancedOsintScanner::new(args).await?;
    let report = scanner.scan().await?;

    // Professional completion message with subtle styling
    println!("    \x1b[38;5;46m▶\x1b[0m \x1b[1;37mScan completed successfully\x1b[0m \x1b[38;5;46m✓\x1b[0m");
    println!("    \x1b[38;5;240m├─\x1b[0m Files processed: \x1b[1;37m{}\x1b[0m", report.scan_info.total_files_scanned);
    println!("    \x1b[38;5;240m├─\x1b[0m Data analyzed: \x1b[1;37m{:.2} MB\x1b[0m", 
        report.scan_info.total_bytes_analyzed as f64 / (1024.0 * 1024.0));
    println!("    \x1b[38;5;240m├─\x1b[0m Duration: \x1b[1;37m{:.2}s\x1b[0m", report.scan_info.duration_seconds);
    
    let high_risk_count = report.assets.iter().filter(|a| a.risk_score > 70).count();
    let (risk_icon, risk_color) = if high_risk_count > 0 { 
        ("⚠", "\x1b[38;5;196m") 
    } else { 
        ("✓", "\x1b[38;5;46m") 
    };
    println!("    \x1b[38;5;240m└─\x1b[0m High-risk assets: {}{}\x1b[0m \x1b[1;37m{}\x1b[0m", risk_color, risk_icon, high_risk_count);
    
    println!();
    println!();

    Ok(())
}