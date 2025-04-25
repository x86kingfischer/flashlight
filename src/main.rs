// flashlight.rs

use chrono::{DateTime, Local};
use serde::Serialize;
use std::time::{Duration, SystemTime};
use windows::Win32::Foundation::*;
use windows::Win32::System::EventLog::*;

#[derive(Serialize)]
struct FlashEvent {
    timestamp: String,
    image_path: String,
    command_line: Option<String>,
    parent_pid: Option<u32>,
    user: Option<String>,
}

fn main() {
    println!("[FLASHLIGHT] Tactical Forensic Console Trigger Scan\n");
    if let Err(e) = scan_event_log() {
        eprintln!("[ERR] Failed to scan logs: {e}");
    }
}

fn scan_event_log() -> windows::core::Result<()> {
    // Target: Event ID 4688 from Security log (Process Creation)
    // Note: Sysmon ID 1 if installed

    let h = unsafe { OpenEventLogW(None, w!("Security")) }?;
    let mut buffer = vec![0u8; 0x10000];
    let mut read = 0;
    let mut needed = 0;
    let mut events = Vec::new();

    unsafe {
        let now = SystemTime::now();
        while ReadEventLogW(
            h,
            EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ,
            0,
            buffer.as_mut_ptr() as *mut _,
            buffer.len() as u32,
            &mut read,
            &mut needed,
        )
        .as_bool()
        {
            let mut offset = 0;
            while offset < read as usize {
                let record = &*(buffer.as_ptr().add(offset) as *const EVENTLOGRECORD);

                let timestamp = SystemTime::UNIX_EPOCH + Duration::from_secs(record.TimeGenerated);
                let dt: DateTime<Local> = timestamp.into();

                if now.duration_since(timestamp).unwrap_or(Duration::MAX) > Duration::from_secs(60)
                {
                    break; // Stop if older than our window
                }

                let source = std::ffi::CStr::from_ptr(
                    (record as *const _ as *const u8).add(std::mem::size_of::<EVENTLOGRECORD>())
                        as *const i8,
                )
                .to_string_lossy()
                .to_string();

                if source != "Microsoft Windows security auditing." {
                    offset += record.Length as usize;
                    continue;
                }

                // Placeholder: In real implementation, parse record.Data here
                let evt = FlashEvent {
                    timestamp: dt.format("%Y-%m-%d %H:%M:%S").to_string(),
                    image_path: "[MockedPath.exe]".to_string(),
                    command_line: Some("cmd /c whoami".to_string()),
                    parent_pid: Some(1234),
                    user: Some("Operator".to_string()),
                };
                events.push(evt);
                offset += record.Length as usize;
            }
        }
    }

    println!("Recent Execution Events (Last 60s):\n");
    for evt in events {
        println!("[{}] {}", evt.timestamp, evt.image_path);
        if let Some(cmd) = evt.command_line.as_ref() {
            println!("  CMD: {}", cmd);
        }
        if let Some(ppid) = evt.parent_pid {
            println!("  Parent PID: {}", ppid);
        }
        if let Some(user) = evt.user.as_ref() {
            println!("  User: {}", user);
        }
        println!("");
    }

    Ok(())
}
