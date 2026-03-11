# netrecon_engine.spec
# PyInstaller spec to bundle the Python scanner engine into a standalone binary.
# Used by the Windows build pipeline so the app doesn't require Python installed.
#
# Build with:
#   pip install pyinstaller
#   pyinstaller netrecon_engine.spec

import os

block_cipher = None

a = Analysis(
    ['netrecon.py'],
    pathex=[os.getcwd()],
    binaries=[],
    datas=[
        ('src/*.py', 'src'),
    ],
    hiddenimports=[
        'src.scanner',
        'src.cve_correlator',
        'src.osint',
        'src.reporter',
        'src.json_bridge',
        'concurrent.futures',
        'ssl',
        'ipaddress',
        'socket',
        'json',
        'urllib.request',
        'urllib.parse',
        're',
        'dataclasses',
        'typing',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'matplotlib', 'numpy', 'PIL', 'cv2'],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='netrecon_engine',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,          # Console app — output goes to stdout for Electron to read
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',
)
