; PayloadCaptureSuite.nsi
; NSIS Installer Script
;
; What this installer does:
;   1. Installs all application files to Program Files
;   2. Silently installs Npcap (the packet capture driver)
;   3. Creates a Start Menu shortcut
;   4. Creates a Desktop shortcut (optional)
;   5. Registers an Add/Remove Programs entry
;   6. Creates an uninstaller
;
; Prerequisites on the BUILD machine (not the end user's machine):
;   - NSIS 3.x          https://nsis.sourceforge.io/Download
;   - The PyInstaller output folder:  dist/PayloadCaptureSuite/
;   - Npcap installer:  npcap-1.79-oem.exe  (download from https://npcap.com/dist/)
;     Place it in the  installer/  subfolder next to this script.
;
; Build command (run from the PayloadCaptureSuite project root):
;   makensis PayloadCaptureSuite.nsi
;
; Output:  PayloadCaptureSuite_Setup.exe

;---------------------------------------------------------------------------
; General settings
;---------------------------------------------------------------------------

!define APP_NAME        "Payload Capture Suite"
!define APP_EXE         "PayloadCaptureSuite.exe"
!define APP_VERSION     "1.0.0"
!define APP_PUBLISHER   "Payload Capture Suite"
!define APP_URL         "https://github.com/your-repo/PayloadCaptureSuite"

; Registry key for Add/Remove Programs
!define REG_KEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\PayloadCaptureSuite"

; Npcap silent installer — place this file in installer/ before building
!define NPCAP_INSTALLER "installer\npcap-1.79-oem.exe"

;---------------------------------------------------------------------------
; NSIS includes
;---------------------------------------------------------------------------

!include "MUI2.nsh"          ; Modern UI 2 (wizard pages with nice graphics)
!include "LogicLib.nsh"      ; ${If} ${EndIf} etc.
!include "x64.nsh"           ; 64-bit install path detection

;---------------------------------------------------------------------------
; Installer metadata
;---------------------------------------------------------------------------

Name            "${APP_NAME}"
OutFile         "PayloadCaptureSuite_Setup.exe"
InstallDir      "$PROGRAMFILES64\${APP_NAME}"
InstallDirRegKey HKLM "${REG_KEY}" "InstallLocation"
RequestExecutionLevel admin          ; always request UAC elevation
SetCompressor   /SOLID lzma          ; best compression

;---------------------------------------------------------------------------
; Modern UI pages
;---------------------------------------------------------------------------

!define MUI_ABORTWARNING
!define MUI_ICON                 "assets\icons\icon.ico"
!define MUI_UNICON               "assets\icons\icon.ico"
!define MUI_WELCOMEPAGE_TITLE    "Welcome to ${APP_NAME} Setup"
!define MUI_WELCOMEPAGE_TEXT     "This installer will set up ${APP_NAME} on your computer.$\n$\nThe installer will also silently install Npcap, the packet capture driver required for live network monitoring.$\n$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN       "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT  "Launch ${APP_NAME}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE    "LICENSE.txt"    ; create a LICENSE.txt in the project root
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

;---------------------------------------------------------------------------
; Version information (shown in Windows file properties)
;---------------------------------------------------------------------------

VIProductVersion                 "1.0.0.0"
VIAddVersionKey "ProductName"    "${APP_NAME}"
VIAddVersionKey "ProductVersion" "${APP_VERSION}"
VIAddVersionKey "FileVersion"    "${APP_VERSION}"
VIAddVersionKey "FileDescription" "Network Forensics & Packet Analysis"
VIAddVersionKey "LegalCopyright" "© 2026 ${APP_PUBLISHER}"

;---------------------------------------------------------------------------
; Install section
;---------------------------------------------------------------------------

Section "MainSection" SEC_MAIN

  SetOutPath "$INSTDIR"

  ; ── Copy all application files from the PyInstaller output ──────────────
  ; PyInstaller puts everything in dist\PayloadCaptureSuite\
  ; We copy the entire folder tree.
  File /r "dist\PayloadCaptureSuite\*.*"

  ; ── Create the data directory (writable by the app) ─────────────────────
  CreateDirectory "$INSTDIR\data"
  CreateDirectory "$INSTDIR\exports"

  ; ── Install Npcap silently ───────────────────────────────────────────────
  ; /S = silent install
  ; /winpcap_mode=yes = enables WinPcap compatibility (Scapy needs this)
  ; /loopback_support=yes = enables loopback capture
  ; We check first whether Npcap is already installed to avoid reinstalling.
  ReadRegStr $0 HKLM "SOFTWARE\Npcap" "InstallPath"
  ${If} $0 == ""
    DetailPrint "Installing Npcap packet capture driver..."
    SetOutPath "$TEMP"
    File "${NPCAP_INSTALLER}"
    ExecWait '"$TEMP\npcap-1.79-oem.exe" /S /winpcap_mode=yes /loopback_support=yes'
    Delete "$TEMP\npcap-1.79-oem.exe"
  ${Else}
    DetailPrint "Npcap is already installed — skipping."
  ${EndIf}

  ; ── Start Menu shortcut ──────────────────────────────────────────────────
  CreateDirectory "$SMPROGRAMS\${APP_NAME}"
  CreateShortcut  "$SMPROGRAMS\${APP_NAME}\${APP_NAME}.lnk" \
                  "$INSTDIR\${APP_EXE}"                      \
                  ""                                          \
                  "$INSTDIR\${APP_EXE}" 0                    \
                  SW_SHOWNORMAL                               \
                  ""                                          \
                  "Payload Capture Suite — Network Forensics"

  CreateShortcut  "$SMPROGRAMS\${APP_NAME}\Uninstall.lnk"   \
                  "$INSTDIR\Uninstall.exe"

  ; ── Desktop shortcut (optional — user can decline via checkbox) ─────────
  CreateShortcut  "$DESKTOP\${APP_NAME}.lnk"                 \
                  "$INSTDIR\${APP_EXE}"                      \
                  ""                                          \
                  "$INSTDIR\${APP_EXE}" 0

  ; ── Write uninstaller ────────────────────────────────────────────────────
  WriteUninstaller "$INSTDIR\Uninstall.exe"

  ; ── Add/Remove Programs registry entry ──────────────────────────────────
  WriteRegStr   HKLM "${REG_KEY}" "DisplayName"     "${APP_NAME}"
  WriteRegStr   HKLM "${REG_KEY}" "DisplayVersion"  "${APP_VERSION}"
  WriteRegStr   HKLM "${REG_KEY}" "Publisher"       "${APP_PUBLISHER}"
  WriteRegStr   HKLM "${REG_KEY}" "URLInfoAbout"    "${APP_URL}"
  WriteRegStr   HKLM "${REG_KEY}" "InstallLocation" "$INSTDIR"
  WriteRegStr   HKLM "${REG_KEY}" "UninstallString" "$INSTDIR\Uninstall.exe"
  WriteRegStr   HKLM "${REG_KEY}" "DisplayIcon"     "$INSTDIR\${APP_EXE}"
  WriteRegDWORD HKLM "${REG_KEY}" "NoModify"        1
  WriteRegDWORD HKLM "${REG_KEY}" "NoRepair"        1

  ; Estimate installed size (in KB) for Add/Remove Programs display
  ${GetSize} "$INSTDIR" "/S=0K" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${REG_KEY}" "EstimatedSize" "$0"

SectionEnd

;---------------------------------------------------------------------------
; Uninstall section
;---------------------------------------------------------------------------

Section "Uninstall"

  ; Remove application files
  RMDir /r "$INSTDIR"

  ; Remove Start Menu shortcuts
  RMDir /r "$SMPROGRAMS\${APP_NAME}"

  ; Remove Desktop shortcut
  Delete "$DESKTOP\${APP_NAME}.lnk"

  ; Remove registry entries
  DeleteRegKey HKLM "${REG_KEY}"

  ; NOTE: We intentionally do NOT uninstall Npcap here.
  ; Npcap is a shared system component — other applications
  ; (Wireshark, etc.) may depend on it.
  ; The user can uninstall Npcap separately from Add/Remove Programs.

SectionEnd
