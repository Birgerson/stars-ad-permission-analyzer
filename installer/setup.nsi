; Stars - AD Permission Analyzer  |  NSIS Installer Script
; Installiert Stars nach %LOCALAPPDATA%\Stars\ und legt Desktop-Verknuepfung an.
; Installs Stars to %LOCALAPPDATA%\Stars\ and creates a desktop shortcut.

Unicode True
!include "LogicLib.nsh"

!define APP_NAME        "Stars"
!define APP_FULL_NAME   "Stars - AD Permission Analyzer"
!define APP_EXE         "Stars.exe"

; APP_VERSION wird vom Release-Workflow via /DAPP_VERSION=... uebergeben.
; Faellt auf 0.0.0-dev zurueck, wenn der Installer lokal ohne Tag gebaut wird.
; APP_VERSION is passed in by the release workflow via /DAPP_VERSION=...
; Falls back to 0.0.0-dev when the installer is built locally without a tag.
!ifndef APP_VERSION
    !define APP_VERSION "0.0.0-dev"
!endif

!define INSTALL_DIR     "$LOCALAPPDATA\Stars"
!define DATA_DIR        "$APPDATA\Stars"
!define LOG_DIR         "$LOCALAPPDATA\Stars\logs"
!define UNINST_REG_KEY  "Software\Microsoft\Windows\CurrentVersion\Uninstall\Stars"

; ---- Metadaten / Metadata ----
Name            "${APP_FULL_NAME}"
OutFile         "Stars-Setup.exe"
InstallDir      "${INSTALL_DIR}"
InstallDirRegKey HKCU "${UNINST_REG_KEY}" "InstallLocation"
RequestExecutionLevel user

; ---- Seiten / Pages ----
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

    ; Desktop-Verknuepfung / Desktop shortcut
    CreateShortCut "$DESKTOP\Stars.lnk" "$INSTDIR\${APP_EXE}" "" "$INSTDIR\${APP_EXE}" 0 SW_SHOWNORMAL

    ; Startmenue / Start menu
    CreateDirectory "$SMPROGRAMS\Stars"
    CreateShortCut  "$SMPROGRAMS\Stars\Stars.lnk"           "$INSTDIR\${APP_EXE}"
    CreateShortCut  "$SMPROGRAMS\Stars\Stars deinstallieren.lnk" "$INSTDIR\Uninstall.exe"

    ; Deinstallationsprogramm schreiben / Write uninstaller
    WriteUninstaller "$INSTDIR\Uninstall.exe"

    ; Registry-Eintrag fuer "Programme und Features"
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
; Deinstallation
;
; Zwei Sektionen:
;   * "Stars" (RO, Pflicht)            - Programmdateien, Verknuepfungen,
;                                        Registry, Uninstaller selbst.
;   * "Audit-Historie und Logs" (/o)   - Standardmaessig NICHT angehakt.
;                                        Wenn angehakt: %APPDATA%\Stars\
;                                        (SQLite-DB) und
;                                        %LOCALAPPDATA%\Stars\logs\
;                                        werden mit entfernt.
;
; Die Trennung schuetzt die Audit-Historie als Beweismittel:
; Standardmaessig bleibt sie erhalten und ueberlebt eine Stars-
; Neuinstallation. Wer alles loswerden will, haken die Option bewusst an.
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

    ; Prozess-Pruefung: laeuft Stars.exe noch, ist die Deinstallation
    ; unzuverlaessig (Dateien gesperrt). Wir versuchen die EXE zu loeschen;
    ; faellt der Versuch fehl, brechen wir mit klarer Meldung ab.
    ; Process check: if Stars.exe is still running, uninstallation is
    ; unreliable (locked files). We try to delete the EXE; if that fails
    ; we abort with a clear message.
    ${If} ${FileExists} "$INSTDIR\${APP_EXE}"
        ClearErrors
        Delete "$INSTDIR\${APP_EXE}"
        ${If} ${Errors}
            MessageBox MB_ICONEXCLAMATION|MB_OK "Stars laeuft noch.$\r$\nBitte schliessen und die Deinstallation neu starten."
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
    Delete "$SMPROGRAMS\Stars\Stars deinstallieren.lnk"
    RMDir  "$SMPROGRAMS\Stars"

    DeleteRegKey HKCU "${UNINST_REG_KEY}"
SectionEnd

Section /o "un.Audit-Historie und Logs entfernen" SecUninstData
    ; Optional: vollstaendige Bereinigung der Benutzerdaten.
    ; Standardmaessig ausgeschaltet, damit die Historie eine
    ; Neuinstallation ueberlebt - wer alles loswerden will, haakt
    ; bewusst an.
    ; Optional: full cleanup of user data. Off by default so the
    ; history survives reinstallation - removing it requires a
    ; deliberate opt-in.
    RMDir /r "${LOG_DIR}"
    RMDir /r "${DATA_DIR}"
SectionEnd
