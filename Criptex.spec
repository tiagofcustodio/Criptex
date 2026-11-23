# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'torch', 'torchvision', 'torchaudio', 'scipy', 'sklearn', 'scikit-learn',
        'pandas', 'matplotlib', 'numpy', 'cv2', 'tensorflow', 'transformers',
        'chromadb', 'onnxruntime', 'pyarrow', 'sympy', 'accelerate', 'ctranslate2',
        'faster_whisper', 'sentence_transformers', 'tokenizers', 'huggingface_hub',
        'boto3', 'botocore', 'google', 'grpc', 'sqlalchemy', 'fastapi', 'uvicorn',
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='Criptex',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=False,
)
