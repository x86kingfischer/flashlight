use chrono::{DateTime, Local};
use serde::Serialize;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, SystemTime};
use widestring::U16CString;
use windows::core::PCWSTR;
use windows::Win32::System::EventLog::{OpenEventLogW, ReadEventLogW, EVENTLOGRECORD};

const EVENTLOG_SEQUENTIAL_READ: u32 = 0x0001;
const EVENTLOG_BACKWARDS_READ: u32 = 0x0008;

const RED: &str = "\x1b[31m";
const YELLOW: &str = "\x1b[33m";
const RESET: &str = "\x1b[0m";

#[derive(Serialize)]
struct FlashEvent {
    timestamp: String,
    image_path: String,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    user: Option<String>,
}

fn to_pwstr(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

fn main() {
    println!("[FLASHLIGHT] Looking for what just ran...\n");
    match scan_event_log() {
        Ok(found) if found => {}
        _ => {
            println!("[!] No event logs found. Switching to PREFETCH fallback.\n");
            scan_prefetch_fallback();
        }
    }
}

fn classify_color(image_path: &str) -> &str {
    let lowered = image_path.to_ascii_lowercase();
    if lowered.contains("cmd.exe")
        || lowered.contains("powershell.exe")
        || lowered.contains("wscript.exe")
        || lowered.contains("python.exe")
    {
        RED
    } else if lowered.contains("conhost.exe")
        || lowered.contains("svchost.exe")
        || lowered.contains("explorer.exe")
    {
        YELLOW
    } else {
        RESET
    }
}

fn scan_event_log() -> windows::core::Result<bool> {
    let security = to_pwstr("Security");
    let h = unsafe { OpenEventLogW(None, PCWSTR(security.as_ptr())) }?;
    let mut buffer = vec![0u8; 0x10000];
    let mut read = 0;
    let mut needed = 0;
    let mut events = Vec::new();

    unsafe {
        let now = SystemTime::now();
        while ReadEventLogW(
            h,
            windows::Win32::System::EventLog::READ_EVENT_LOG_READ_FLAGS(
                EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ,
            ),
            0,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut read,
            &mut needed,
        )
        .is_ok()
        {
            let mut offset = 0;
            while offset < read as usize {
                let record = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);

                let timestamp =
                    SystemTime::UNIX_EPOCH + Duration::from_secs(record.TimeGenerated as u64);
                let dt: DateTime<Local> = timestamp.into();

                if now.duration_since(timestamp).unwrap_or(Duration::MAX) > Duration::from_secs(60)
                {
                    break;
                }

                let mut current =
                    buffer.as_ptr().add(offset + record.StringOffset as usize) as *const u16;
                let mut string_vec = Vec::new();

                for _ in 0..record.NumStrings {
                    let s = U16CString::from_ptr_str(current).to_string_lossy();
                    string_vec.push(s);

                    let mut advance = 0;
                    while *current.add(advance) != 0 {
                        advance += 1;
                    }
                    current = current.add(advance + 1);
                }

                let image_path = string_vec
                    .get(5)
                    .cloned()
                    .filter(|s| s.contains("\\") && s.to_lowercase().ends_with(".exe"))
                    .unwrap_or("Unknown".to_string());
                let command_line = string_vec
                    .get(7)
                    .cloned()
                    .filter(|s| !s.starts_with("%%") && s.len() > 2)
                    .or(Some("[n/a]".to_string()));
                let parent_pid = string_vec.get(8).and_then(|s| s.parse().ok());
                let user = if string_vec.len() > 2 {
                    Some(format!("{}\\{}", string_vec[2], string_vec[1]))
                } else {
                    None
                };

                let evt = FlashEvent {
                    timestamp: dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                    image_path,
                    command_line,
                    parent_pid,
                    user,
                };

                if evt.image_path != "Unknown" {
                    events.push(evt);
                }

                offset += record.Length as usize;

                if events.len() >= 10 {
                    break;
                }
            }
        }
    }

    if !events.is_empty() {
        println!("Recent Execution Events (Last 60s):\n");
        for evt in events.iter().rev() {
            let color = classify_color(&evt.image_path);
            println!("────────────────────────────────────────────────────────────");
            println!("{}[{}] {}{}", color, evt.timestamp, evt.image_path, RESET);
            if let Some(cmd) = evt.command_line.as_ref() {
                println!("  CMD       : {}", cmd);
            }
            if let Some(ppid) = evt.parent_pid {
                println!("  ParentPID : {}", ppid);
            }
            if let Some(user) = evt.user.as_ref() {
                println!("  User      : {}", user);
            }
        }
        println!("────────────────────────────────────────────────────────────\n");
        Ok(true)
    } else {
        Ok(false)
    }
}

fn scan_prefetch_fallback() {
    let now = SystemTime::now();
    let prefetch_path = Path::new("C:\\Windows\\Prefetch");

    if let Ok(entries) = fs::read_dir(prefetch_path) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if now.duration_since(modified).unwrap_or(Duration::MAX)
                        < Duration::from_secs(60)
                    {
                        let filename = entry.file_name().to_string_lossy().to_string();
                        if filename.ends_with(".pf") {
                            let color = classify_color(&filename);
                            println!(
                                "{}[PREFETCH] Recently modified: {}{}",
                                color, filename, RESET
                            );
                        }
                    }
                }
            }
        }
    } else {
        println!(
            "[ERR] Unable to read Prefetch directory. Insufficient rights or feature disabled."
        );
    }
}
