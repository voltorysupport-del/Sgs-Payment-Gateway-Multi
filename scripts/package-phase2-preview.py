"""Package only the isolated synthetic preview, reproducibly, with no gateway/config files.

Usage: python scripts/package-phase2-preview.py <output-directory>
No source build, dependency install, environment credentials or database connection.
"""
import hashlib
import json
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'local-preview-phase2'
PREFIX = 'VaultX-Pay-Phase2-Preview'
EXPECTED = {
    'Preview-Dashboard.cmd', 'Test-Preview.cmd', 'START-HERE.md', 'SOURCE.json',
    'public/index.html', 'public/styles.css', 'public/app.js',
    'scripts/server.mjs', 'scripts/verify.mjs',
    'tests/smoke.test.mjs', 'tests/integrity.test.mjs', 'tests/browser-smoke.mjs', 'tests/launcher-smoke.mjs',
}

def digest(data):
    return hashlib.sha256(data).hexdigest()


def main():
    output = Path(sys.argv[1]).resolve()
    if output == SOURCE or SOURCE in output.parents:
        raise ValueError('Output must be outside the source package.')
    actual = {p.relative_to(SOURCE).as_posix() for p in SOURCE.rglob('*') if p.is_file()}
    if actual != EXPECTED or any(p.is_symlink() for p in SOURCE.rglob('*')):
        raise ValueError('Unexpected or missing preview source file.')
    output.mkdir(parents=True, exist_ok=True)
    archive = output / 'vaultx-pay-phase2-preview.zip'
    if archive.exists():
        raise ValueError('Refusing to overwrite an existing archive.')
    data = {p: (SOURCE / p).read_bytes() for p in sorted(EXPECTED)}
    # CMD launchers have identical CRLF bytes on Linux and Windows checkouts.
    for name in ('Preview-Dashboard.cmd', 'Test-Preview.cmd'):
        data[name] = data[name].replace(b'\r\n', b'\n').replace(b'\n', b'\r\n')
    manifest = json.dumps({'algorithm': 'SHA-256', 'files': {p: digest(b) for p, b in data.items()}}, indent=2) + '\n'
    data['SHA256SUMS.json'] = manifest.encode('utf-8')
    with zipfile.ZipFile(archive, 'x', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name, content in sorted(data.items()):
            info = zipfile.ZipInfo(PREFIX + '/' + name, date_time=(2026, 10, 26, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            package.writestr(info, content, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with zipfile.ZipFile(archive) as package:
        if package.testzip() is not None or set(package.namelist()) != {PREFIX + '/' + p for p in data}:
            raise ValueError('Archive integrity verification failed.')
    hashfile = output / 'vaultx-pay-phase2-preview.zip.sha256'
    hashfile.write_text(digest(archive.read_bytes()) + '  ' + archive.name + '\n', encoding='utf-8')
    print(json.dumps({'archive': archive.name, 'bytes': archive.stat().st_size, 'files': len(data), 'sha256': digest(archive.read_bytes())}))


if __name__ == '__main__':
    main()
