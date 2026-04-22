//! Cross-platform "install the daemon so it starts on login" helper.
//!
//! `install_autostart()` figures out the running OS, drops the appropriate
//! init-system file (systemd user unit / launchd plist / Scheduled Task
//! XML) pointing at the *currently running* binary, and loads it. No
//! manual edits needed.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

pub fn install_autostart() -> Result<()> {
    let exe = std::env::current_exe()
        .context("couldn't resolve current binary path")?;
    let exe = exe.to_string_lossy().to_string();

    ensure_paired()?;

    #[cfg(target_os = "linux")]
    { return install_systemd_user(&exe); }

    #[cfg(target_os = "macos")]
    { return install_launchd(&exe); }

    #[cfg(target_os = "windows")]
    { return install_task_scheduler(&exe); }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        let _ = exe;
        bail!("autostart install is not implemented for this OS — run \
               `whatsapp-rs daemon` manually or via your init system");
    }
}

pub fn uninstall_autostart() -> Result<()> {
    #[cfg(target_os = "linux")]
    { return uninstall_systemd_user(); }

    #[cfg(target_os = "macos")]
    { return uninstall_launchd(); }

    #[cfg(target_os = "windows")]
    { return uninstall_task_scheduler(); }

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    { bail!("autostart uninstall is not implemented for this OS"); }
}

fn ensure_paired() -> Result<()> {
    use crate::auth::{AuthManager, AuthState, FileStore};
    let store = std::sync::Arc::new(FileStore::new()?);
    let mgr = AuthManager::new(store)?;
    if *mgr.state() != AuthState::Authenticated {
        bail!(
            "not paired yet. Run `whatsapp-rs listen` once and scan the QR \
             before installing the daemon — otherwise it has no way to \
             complete pairing."
        );
    }
    Ok(())
}

// ── Linux / systemd user unit ────────────────────────────────────────────────

#[cfg(target_os = "linux")]
fn systemd_unit_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("no HOME")?;
    Ok(home.join(".config/systemd/user/whatsapp-rs.service"))
}

#[cfg(target_os = "linux")]
fn install_systemd_user(exe: &str) -> Result<()> {
    let unit = format!(
        "[Unit]\n\
        Description=whatsapp-rs daemon (persistent WhatsApp Web session)\n\
        After=network-online.target\n\
        Wants=network-online.target\n\
        \n\
        [Service]\n\
        Type=simple\n\
        ExecStart={exe} daemon\n\
        Restart=on-failure\n\
        RestartSec=3\n\
        StandardOutput=journal\n\
        StandardError=journal\n\
        Environment=RUST_LOG=info,whatsapp_rs=info\n\
        \n\
        [Install]\n\
        WantedBy=default.target\n",
    );
    let path = systemd_unit_path()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, unit)?;
    println!("wrote {}", path.display());

    run("systemctl", &["--user", "daemon-reload"])?;
    run("systemctl", &["--user", "enable", "--now", "whatsapp-rs.service"])?;
    // Best-effort: also survive across reboots while the user is logged out.
    let _ = std::process::Command::new("loginctl")
        .args(["enable-linger", &whoami()?])
        .status();

    println!("\ninstalled. Tail logs:\n  journalctl --user -u whatsapp-rs -f");
    Ok(())
}

#[cfg(target_os = "linux")]
fn uninstall_systemd_user() -> Result<()> {
    let _ = run("systemctl", &["--user", "disable", "--now", "whatsapp-rs.service"]);
    let path = systemd_unit_path()?;
    let _ = std::fs::remove_file(&path);
    let _ = run("systemctl", &["--user", "daemon-reload"]);
    println!("removed {}", path.display());
    Ok(())
}

// ── macOS / launchd ──────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
fn launchd_plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("no HOME")?;
    Ok(home.join("Library/LaunchAgents/com.whatsapp-rs.plist"))
}

#[cfg(target_os = "macos")]
fn install_launchd(exe: &str) -> Result<()> {
    let log = "/tmp/whatsapp-rs.log";
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>com.whatsapp-rs</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>daemon</string>
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key>
    <dict><key>SuccessfulExit</key><false/></dict>
    <key>StandardOutPath</key><string>{log}</string>
    <key>StandardErrorPath</key><string>{log}</string>
    <key>EnvironmentVariables</key>
    <dict><key>RUST_LOG</key><string>info,whatsapp_rs=info</string></dict>
</dict>
</plist>
"#);

    let path = launchd_plist_path()?;
    std::fs::create_dir_all(path.parent().unwrap())?;
    std::fs::write(&path, plist)?;
    println!("wrote {}", path.display());

    // Unload first in case a stale copy is loaded.
    let _ = run("launchctl", &["unload", path.to_str().unwrap()]);
    run("launchctl", &["load", "-w", path.to_str().unwrap()])?;

    println!("\ninstalled. Tail logs:\n  tail -f {log}");
    Ok(())
}

#[cfg(target_os = "macos")]
fn uninstall_launchd() -> Result<()> {
    let path = launchd_plist_path()?;
    if path.exists() {
        let _ = run("launchctl", &["unload", path.to_str().unwrap()]);
        std::fs::remove_file(&path)?;
        println!("removed {}", path.display());
    } else {
        println!("no launchd plist installed");
    }
    Ok(())
}

// ── Windows / Task Scheduler ─────────────────────────────────────────────────

#[cfg(target_os = "windows")]
fn install_task_scheduler(exe: &str) -> Result<()> {
    // XML with the actual exe path baked in.
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author">
    <LogonType>InteractiveToken</LogonType>
    <RunLevel>LeastPrivilege</RunLevel>
  </Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <Enabled>true</Enabled>
    <RestartOnFailure><Interval>PT10S</Interval><Count>9999</Count></RestartOnFailure>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{exe}</Command>
      <Arguments>daemon</Arguments>
    </Exec>
  </Actions>
</Task>
"#);

    let tmp = std::env::temp_dir().join("whatsapp-rs-task.xml");
    // Windows Task Scheduler wants UTF-16 LE with BOM.
    let mut bytes = vec![0xFF, 0xFE];
    for u in xml.encode_utf16() {
        bytes.extend(&u.to_le_bytes());
    }
    std::fs::write(&tmp, &bytes)?;

    run("schtasks", &["/Create", "/F", "/TN", "whatsapp-rs", "/XML", tmp.to_str().unwrap()])?;
    // Fire once right now so the user doesn't have to reboot to start it.
    let _ = run("schtasks", &["/Run", "/TN", "whatsapp-rs"]);
    println!("installed scheduled task \"whatsapp-rs\"");
    Ok(())
}

#[cfg(target_os = "windows")]
fn uninstall_task_scheduler() -> Result<()> {
    let _ = run("schtasks", &["/End", "/TN", "whatsapp-rs"]);
    run("schtasks", &["/Delete", "/F", "/TN", "whatsapp-rs"])?;
    println!("removed scheduled task \"whatsapp-rs\"");
    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn run(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .status()
        .with_context(|| format!("failed to spawn `{cmd}`"))?;
    if !status.success() {
        bail!("`{cmd} {}` exited with {status}", args.join(" "));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn whoami() -> Result<String> {
    let out = std::process::Command::new("whoami").output()?;
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}
