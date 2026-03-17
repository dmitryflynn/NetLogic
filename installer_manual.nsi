; ============================================================
;  NetLogic Installer — NSIS Script
;  Produces: NetLogic-2.0.0-Setup.exe
;
;  Requirements:
;    NSIS 3.x  https://nsis.sourceforge.io/Download
;    Place this file in the same directory as your dist/ folder
;    after running PyInstaller.
;
;  Build:
;    makensis installer.nsi
; ============================================================

!define APP_NAME        "NetLogic"
!define APP_VERSION     "2.0.0"
!define APP_PUBLISHER   "NetLogic Security Tools"
!define APP_URL         "https://github.com/YOUR_USERNAME/netlogic"
!define APP_EXE         "netlogic.exe"
!define INSTALL_DIR     "$PROGRAMFILES64\NetLogic"
!define UNINSTALL_KEY   "Software\Microsoft\Windows\CurrentVersion\Uninstall\NetLogic"
!define MUI_ICON        "netlogic.ico"     ; Optional — comment out if no icon
!define MUI_UNICON      "netlogic.ico"

; ── Includes ────────────────────────────────────────────────
!include "MUI2.nsh"
!include "LogicLib.nsh"
!include "WinMessages.nsh"
!include "x64.nsh"

; ── Installer metadata ──────────────────────────────────────
Name          "${APP_NAME} ${APP_VERSION}"
OutFile       "NetLogic-${APP_VERSION}-Setup.exe"
InstallDir    "${INSTALL_DIR}"
InstallDirRegKey HKLM "${UNINSTALL_KEY}" "InstallLocation"
RequestExecutionLevel admin
SetCompressor /SOLID lzma
Unicode True

; ── MUI Pages ───────────────────────────────────────────────
!define MUI_ABORTWARNING
!define MUI_WELCOMEPAGE_TITLE     "Welcome to NetLogic ${APP_VERSION} Setup"
!define MUI_WELCOMEPAGE_TEXT      "NetLogic is an attack surface mapper and vulnerability correlator.$\r$\n$\r$\nThis wizard will install NetLogic ${APP_VERSION} on your computer.$\r$\n$\r$\nClick Next to continue."
!define MUI_FINISHPAGE_RUN        "$INSTDIR\${APP_EXE}"
!define MUI_FINISHPAGE_RUN_TEXT   "Open a terminal in the install directory"
!define MUI_FINISHPAGE_SHOWREADME "$INSTDIR\README.md"
!define MUI_FINISHPAGE_SHOWREADME_TEXT "View README"
!define MUI_FINISHPAGE_LINK       "NetLogic on GitHub"
!define MUI_FINISHPAGE_LINK_LOCATION "${APP_URL}"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE     "LICENSE"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

!insertmacro MUI_LANGUAGE "English"

; ── Version Info ────────────────────────────────────────────
VIProductVersion                  "2.0.0.0"
VIAddVersionKey "ProductName"     "${APP_NAME}"
VIAddVersionKey "ProductVersion"  "${APP_VERSION}"
VIAddVersionKey "CompanyName"     "${APP_PUBLISHER}"
VIAddVersionKey "FileDescription" "NetLogic Installer"
VIAddVersionKey "FileVersion"     "${APP_VERSION}"
VIAddVersionKey "LegalCopyright"  "For authorized security assessments only"

; ============================================================
;  COMPONENTS
; ============================================================

Section "NetLogic Core" SecCore
  SectionIn RO   ; Required — cannot be deselected
  
  SetOutPath "$INSTDIR"
  
  ; Main executable (PyInstaller single-file bundle)
  File "dist\netlogic.exe"
  
  ; Documentation
  File "README.md"
  File "LICENSE"
  
  ; Write uninstaller
  WriteUninstaller "$INSTDIR\Uninstall.exe"
  
  ; Add/Remove Programs registry entry
  WriteRegStr   HKLM "${UNINSTALL_KEY}" "DisplayName"          "${APP_NAME} ${APP_VERSION}"
  WriteRegStr   HKLM "${UNINSTALL_KEY}" "UninstallString"      "$INSTDIR\Uninstall.exe"
  WriteRegStr   HKLM "${UNINSTALL_KEY}" "InstallLocation"      "$INSTDIR"
  WriteRegStr   HKLM "${UNINSTALL_KEY}" "Publisher"            "${APP_PUBLISHER}"
  WriteRegStr   HKLM "${UNINSTALL_KEY}" "URLInfoAbout"         "${APP_URL}"
  WriteRegStr   HKLM "${UNINSTALL_KEY}" "DisplayVersion"       "${APP_VERSION}"
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoModify"             1
  WriteRegDWORD HKLM "${UNINSTALL_KEY}" "NoRepair"             1

SectionEnd

Section "Add to System PATH" SecPath
  ; Add install dir to system PATH so 'netlogic' works from any terminal
  
  ; Read existing PATH
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  
  ; Only add if not already present
  ${StrContains} $1 "$INSTDIR" "$0"
  StrCmp $1 "" 0 PathAlreadyExists
    WriteRegExpandStr HKLM \
      "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" \
      "Path" "$0;$INSTDIR"
    ; Broadcast WM_SETTINGCHANGE so open terminals pick it up
    SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
    DetailPrint "Added $INSTDIR to system PATH"
    Goto PathDone
  PathAlreadyExists:
    DetailPrint "PATH already contains $INSTDIR"
  PathDone:
SectionEnd

Section "Desktop Shortcut" SecDesktop
  CreateShortcut "$DESKTOP\NetLogic Terminal.lnk" \
    "cmd.exe" \
    '/K "cd /d $INSTDIR && echo NetLogic ready. Type: netlogic.exe --help"' \
    "$INSTDIR\${APP_EXE}" 0
SectionEnd

Section "Start Menu Shortcuts" SecStartMenu
  CreateDirectory "$SMPROGRAMS\NetLogic"
  
  ; Open CMD in install dir
  CreateShortcut "$SMPROGRAMS\NetLogic\NetLogic Terminal.lnk" \
    "cmd.exe" \
    '/K "cd /d $INSTDIR && netlogic.exe --help"' \
    "$INSTDIR\${APP_EXE}" 0
  
  ; README
  CreateShortcut "$SMPROGRAMS\NetLogic\README.lnk" \
    "$INSTDIR\README.md"
  
  ; Uninstaller
  CreateShortcut "$SMPROGRAMS\NetLogic\Uninstall NetLogic.lnk" \
    "$INSTDIR\Uninstall.exe"
SectionEnd

; ── Component descriptions ────────────────────────────────────
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
  !insertmacro MUI_DESCRIPTION_TEXT ${SecCore}      "NetLogic executable and documentation. Required."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecPath}      "Add NetLogic to system PATH — run 'netlogic' from any terminal window."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop}   "Add a shortcut to your Desktop that opens a terminal ready to use NetLogic."
  !insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Add NetLogic to the Start Menu."
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; ============================================================
;  UNINSTALLER
; ============================================================

Section "Uninstall"
  ; Remove files
  Delete "$INSTDIR\netlogic.exe"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\Uninstall.exe"
  RMDir  "$INSTDIR"
  
  ; Remove shortcuts
  Delete "$DESKTOP\NetLogic Terminal.lnk"
  Delete "$SMPROGRAMS\NetLogic\*.*"
  RMDir  "$SMPROGRAMS\NetLogic"
  
  ; Remove from PATH
  ReadRegStr $0 HKLM "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" "Path"
  ${WordReplace} "$0" ";$INSTDIR" "" "+" $1
  WriteRegExpandStr HKLM \
    "SYSTEM\CurrentControlSet\Control\Session Manager\Environment" \
    "Path" "$1"
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000
  
  ; Remove Add/Remove Programs entry
  DeleteRegKey HKLM "${UNINSTALL_KEY}"
  
  ; Ask user if they want to remove the NVD cache
  MessageBox MB_YESNO "Remove NetLogic NVD cache? ($PROFILE\.netlogic\)" IDNO SkipCache
    RMDir /r "$PROFILE\.netlogic"
  SkipCache:
  
  DetailPrint "NetLogic has been uninstalled."
SectionEnd

; ============================================================
;  HELPER FUNCTIONS
; ============================================================

; StrContains — checks if $2 is a substring of $1, result in $0
!macro _StrContainsConstructor OUT NEEDLE HAYSTACK
  Push "${HAYSTACK}"
  Push "${NEEDLE}"
  Call StrContains
  Pop "${OUT}"
!macroend
!define StrContains '!insertmacro "_StrContainsConstructor"'

Function StrContains
  Exch $R0   ; NEEDLE
  Exch
  Exch $R1   ; HAYSTACK
  Push $R2
  Push $R3
  Push $R4
  StrLen $R2 $R0
  StrLen $R3 $R1
  IntOp $R3 $R3 - $R2
  IntOp $R3 $R3 + 1
  StrCpy $R4 0
  loop:
    IntCmp $R4 $R3 done done
    StrCpy $R2 $R1 ${NSIS_MAX_STRLEN} $R4
    StrCmp $R2 $R0 found
    IntOp $R4 $R4 + 1
    Goto loop
  found:
    StrCpy $R0 $R1 "" $R4
    Goto done2
  done:
    StrCpy $R0 ""
  done2:
  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Exch $R0
FunctionEnd
