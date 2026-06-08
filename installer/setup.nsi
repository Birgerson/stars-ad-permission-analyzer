; Stars - AD Permission Analyzer  |  NSIS Installer Script
; Installs Stars to %LOCALAPPDATA%\Stars\ and creates a desktop shortcut.

Unicode True
!include "LogicLib.nsh"

!define APP_NAME        "Stars"
!define APP_FULL_NAME   "Stars - AD Permission Analyzer"
!define APP_EXE         "Stars.exe"

; APP_VERSION is passed in by the release workflow via /DAPP_VERSION=...
; Falls back to 0.0.0-dev when the installer is built locally without a tag.
!ifndef APP_VERSION
    !define APP_VERSION "0.0.0-dev"
!endif

!define INSTALL_DIR     "$LOCALAPPDATA\Stars"
!define DATA_DIR        "$APPDATA\Stars"
!define LOG_DIR         "$LOCALAPPDATA\Stars\logs"
!define UNINST_REG_KEY  "Software\Microsoft\Windows\CurrentVersion\Uninstall\Stars"

; ---- Metadata ----
Name            "${APP_FULL_NAME}"
OutFile         "Stars-Setup.exe"
InstallDir      "${INSTALL_DIR}"
InstallDirRegKey HKCU "${UNINST_REG_KEY}" "InstallLocation"
RequestExecutionLevel user

; ---- Pages ----
Page instfiles
UninstPage components
UninstPage instfiles

; ---------------------------------------------------------------------------
; Installation
; ---------------------------------------------------------------------------
Section "Stars" SecMain
    SectionIn RO

    SetOutPath "$INSTDIR"
    File "${APP_EXE}"

    ; Desktop shortcut
    CreateShortCut "$DESKTOP\Stars.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0 SW_SHOWNORMAL

    ; Start menu
    CreateDirectory "$SMPROGRAMS\Stars"
    CreateShortCut  "$SMPROGRAMS\Stars\Stars.lnk"           "$INSTDIR\${APP_EXE}"
    CreateShortCut  "$SMPROGRAMS\Stars\Uninstall Stars.lnk" "$INSTDIR\Uninstall.exe"

    ; Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; "Programs and Features" registry entry
    WriteRegStr   HKCU "${UNINST_REG_KEY}" "DisplayName"     "${APP_FULL_NAME}"
    WriteRegStr   HKCU "${UNINST_REG_KEY}" "UninstallString" '"$INSTDIR\Uninstall.exe"'
    WriteRegStr   HKCU "${UNINST_REG_KEY}" "InstallLocation" "$INSTDIR"
    WriteRegStr   HKCU "${UNINST_REG_KEY}" "DisplayVersion"  "${APP_VERSION}"
    WriteRegStr   HKCU "${UNINST_REG_KEY}" "Publisher"       "Birger Labinsch"
    WriteRegDWORD HKCU "${UNINST_REG_KEY}" "NoModify"        1
    WriteRegDWORD HKCU "${UNINST_REG_KEY}" "NoRepair"        1

SectionEnd

; ---------------------------------------------------------------------------
; Uninstallation
;
; Two sections:
;   * "Stars" (RO, mandatory)          - program files, shortcuts,
;                                        registry, uninstaller itself.
;   * "Audit history and logs" (/o)    - NOT checked by default.
;                                        When checked: %APPDATA%\Stars\
;                                        (SQLite DB) and
;                                        %LOCALAPPDATA%\Stars\logs\ are
;                                        removed as well.
;
; The split protects the audit history as evidence: by default it survives
; uninstallation and reinstall. Removing it requires a deliberate opt-in.
; ---------------------------------------------------------------------------

Section "un.Pre" SecUninstPre
    SectionIn RO

    ; Process check: if Stars.exe is still running, uninstallation is
    ; unreliable (locked files). We try to delete the EXE; if that fails
    ; we abort with a clear message.
    ${If} ${FileExists} "$INSTDIR\${APP_EXE}"
        ClearErrors
        Delete "$INSTDIR\${APP_EXE}"
        ${If} ${Errors}
            MessageBox MB_ICONEXCLAMATION|MB_OK "Stars is still running.$\r$\nPlease close it and restart the uninstaller."
            Abort
        ${EndIf}
    ${EndIf}
SectionEnd

Section "un.Stars" SecUninstMain
    SectionIn RO

    Delete "$INSTDIR\Uninstall.exe"
    RMDir  "$INSTDIR"

    Delete "$DESKTOP\Stars.lnk"
    Delete "$SMPROGRAMS\Stars\Stars.lnk"
    Delete "$SMPROGRAMS\Stars\Uninstall Stars.lnk"
    RMDir  "$SMPROGRAMS\Stars"

    DeleteRegKey HKCU "${UNINST_REG_KEY}"
SectionEnd

Section /o "un.Remove audit history and logs" SecUninstData
    ; Optional: full cleanup of user data. Off by default so the
    ; history survives reinstallation - removing it requires a
    ; deliberate opt-in.
    RMDir /r "${LOG_DIR}"
    RMDir /r "${DATA_DIR}"
SectionEnd
