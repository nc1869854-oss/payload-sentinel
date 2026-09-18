# Troubleshooting — Payload Capture Suite

## Build problems

### "Python not found"
Install Python 3.10+ from python.org.
During install, tick **Add Python to PATH**.
Then open a new terminal and re-run `build.bat`.

### "NSIS not found"
Install NSIS 3.x from https://nsis.sourceforge.io/Download.
The installer adds NSIS to PATH. Re-run `build.bat` after installing.

### "Npcap installer not found"
Download `npcap-1.79-oem.exe` from https://npcap.com/dist/
and place it in the `installer\` folder inside the project root.

### PyInstaller fails with "ModuleNotFoundError"
A hidden import was missed. Add the module name to the
`hiddenimports` list in `PayloadCaptureSuite.spec`, then re-run:
```
python -m PyInstaller PayloadCaptureSuite.spec --noconfirm
```

### PyInstaller fails with "Access Denied" or antivirus warning
Antivirus software sometimes blocks PyInstaller from reading or writing
files. Temporarily disable real-time protection during the build,
or add the project folder to your AV exclusion list.

### NSIS fails with "Can't open file: assets\icons\icon.ico"
Either create an `assets\icons\icon.ico` file, or edit
`PayloadCaptureSuite.nsi` and `PayloadCaptureSuite.spec` to remove
the icon references.

---

## Installer / runtime problems

### The installer says "This app requires Windows..."
The installer requires a 64-bit version of Windows 10 or 11.

### "Windows protected your PC" (SmartScreen warning)
This appears for unsigned executables. Click **More info → Run anyway**.
To remove this warning permanently, sign the exe with a code-signing
certificate from a CA like Sectigo or DigiCert.

### App opens but no interfaces appear in the dropdown
Npcap was not installed, or the installation failed silently.
Open **Add or Remove Programs**, search for Npcap, and reinstall it
manually from https://npcap.com.

### "Access denied" when starting capture
The app must run as Administrator. Right-click the shortcut →
**Run as Administrator**. The installer's UAC manifest should trigger
this automatically — if it doesn't, check that the manifest is
embedded in the exe (use `sigcheck -m PayloadCaptureSuite.exe`).

### Capture starts but no packets appear
1. Confirm the correct interface is selected.
2. Confirm Npcap is installed with WinPcap-compatible mode enabled.
3. Check Windows Firewall is not blocking Npcap's drivers.
4. Try running as Administrator if not already.

### PDF reports fail with "ReportLab not found"
ReportLab should be bundled by PyInstaller. If it fails:
1. Run `python -m pip install reportlab` on the build machine.
2. Re-run `build.bat`.

### "database is locked" error
Only one instance of the application should be open at a time.
Close any other running copies. If the error persists, the database
file may be corrupted — back it up and delete
`data\payloadcapture.db` to start fresh.

### Settings are lost after update
Settings are stored in:
`%APPDATA%\PayloadCaptureSuite\settings.json`
This folder is not removed during update or uninstall.
If settings are reset, it means the file was not writable —
check folder permissions.

---

## Uninstalling

Use **Add or Remove Programs** → search for **Payload Capture Suite**
→ Uninstall.

Note: The uninstaller does NOT remove Npcap, because Npcap is shared
with other tools like Wireshark. Uninstall Npcap separately if you
want to remove it.

The uninstaller also leaves the `data\` and `exports\` folders inside
the install directory, so your investigation sessions and reports are
preserved. Delete them manually if you want a clean removal.
