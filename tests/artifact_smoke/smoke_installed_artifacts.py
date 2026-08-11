#!/usr/bin/env python3
"""Install staged release artifacts into a clean consumer and exercise them."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--consumer-dir", type=Path, required=True)
    return parser.parse_args()


def run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> str:
    printable = " ".join(command)
    print(f"+ ({cwd}) {printable}")
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.stdout:
        print(result.stdout.rstrip())
    if result.stderr:
        print(result.stderr.rstrip(), file=sys.stderr)
    return result.stdout


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def only_file(directory: Path, pattern: str) -> Path:
    matches = sorted(directory.glob(pattern))
    if len(matches) != 1:
        raise RuntimeError(f"expected one {pattern} under {directory}, found {matches}")
    return matches[0]


def validate_provenance(artifact_dir: Path) -> dict[str, object]:
    provenance_path = artifact_dir / "provenance.json"
    provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
    if provenance.get("schema") != 1:
        raise RuntimeError(f"unsupported provenance: {provenance}")
    files = provenance.get("files")
    if not isinstance(files, dict) or len(files) != 4:
        raise RuntimeError(f"provenance must describe exactly four packages: {files}")
    for relative, expected in files.items():
        artifact = artifact_dir / relative
        if not artifact.is_file():
            raise RuntimeError(f"provenance artifact is missing: {artifact}")
        actual_hash = sha256(artifact)
        actual_size = artifact.stat().st_size
        if actual_hash != expected["sha256"] or actual_size != expected["bytes"]:
            raise RuntimeError(f"artifact digest mismatch: {artifact}")
    print("Verified artifact provenance:")
    print(json.dumps(provenance, indent=2, sort_keys=True))
    return provenance


def validate_wheel(wheel: Path) -> None:
    with zipfile.ZipFile(wheel) as archive:
        members = archive.namelist()
    if not any(name.endswith(".dist-info/METADATA") for name in members):
        raise RuntimeError(f"wheel has no package metadata: {wheel}")
    if not any(name.endswith((".so", ".pyd")) for name in members):
        raise RuntimeError(f"wheel has no native extension: {wheel}")


def package_metadata(archive: tarfile.TarFile) -> dict[str, object]:
    package_json = archive.extractfile("package/package.json")
    if package_json is None:
        raise RuntimeError("npm tarball does not contain package/package.json")
    return json.load(package_json)


def validate_npm_tarballs(
    root_tarball: Path, native_tarball: Path, expected_native_name: str
) -> tuple[str, bytes]:
    with tarfile.open(root_tarball, "r:gz") as archive:
        members = {member.name for member in archive.getmembers() if member.isfile()}
        metadata = package_metadata(archive)
    if metadata.get("name") != "rookie-cookies":
        raise RuntimeError(f"unexpected npm root metadata: {metadata}")
    required = {"package/package.json", "package/index.js", "package/index.d.ts"}
    if not required.issubset(members):
        raise RuntimeError(f"npm root package is missing {required - members}")
    if any(name.endswith(".node") for name in members):
        raise RuntimeError("npm root package must not embed a platform binding")

    with tarfile.open(native_tarball, "r:gz") as archive:
        native_members = {
            member.name for member in archive.getmembers() if member.isfile()
        }
        native_metadata = package_metadata(archive)
        native_entry = native_metadata.get("main")
        if not isinstance(native_entry, str):
            raise RuntimeError(f"native package has no main entry: {native_metadata}")
        binary_member = f"package/{native_entry}"
        stream = archive.extractfile(binary_member)
        if stream is None:
            raise RuntimeError(f"native tarball is missing {binary_member}")
        native_binary = stream.read()
    if native_metadata.get("name") != expected_native_name:
        raise RuntimeError(
            f"expected native npm package {expected_native_name}, got {native_metadata}"
        )
    if binary_member not in native_members or not native_entry.endswith(".node"):
        raise RuntimeError(f"invalid native npm package contents: {native_members}")
    return native_entry, native_binary


def seed_firefox_database(database: Path) -> None:
    database.parent.mkdir(parents=True)
    connection = sqlite3.connect(database)
    connection.execute(
        """
        CREATE TABLE moz_cookies (
          host TEXT NOT NULL,
          path TEXT NOT NULL,
          isSecure INTEGER NOT NULL,
          expiry INTEGER NOT NULL,
          name TEXT NOT NULL,
          value TEXT NOT NULL,
          isHttpOnly INTEGER NOT NULL,
          sameSite INTEGER NOT NULL
        )
        """
    )
    connection.executemany(
        """
        INSERT INTO moz_cookies
          (host, path, isSecure, expiry, name, value, isHttpOnly, sameSite)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        [
            (
                ".artifact.test",
                "/",
                1,
                2_000_000_000,
                "rookie_artifact",
                "installed-ok",
                1,
                1,
            ),
            ("decoy.invalid", "/", 0, 2_000_000_000, "decoy", "filtered", 0, 0),
        ],
    )
    connection.commit()
    connection.close()


def venv_python(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def smoke_cli(cli: Path, database: Path, consumer: Path) -> None:
    cli.chmod(cli.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    version = run([str(cli), "--version"], cwd=consumer)
    if "CLI:" not in version or "rookie-cookies:" not in version:
        raise RuntimeError(f"unexpected CLI version output: {version}")
    output = run(
        [
            str(cli),
            "--path",
            str(database),
            "--domains",
            "artifact.test",
            "--format",
            "json",
        ],
        cwd=consumer,
        env={**os.environ, "RUST_LOG": "error"},
    )
    cookies = json.loads(output)
    if len(cookies) != 1 or cookies[0].get("name") != "rookie_artifact":
        raise RuntimeError(f"CLI did not return the filtered fixture: {cookies}")
    if cookies[0].get("value") != "installed-ok":
        raise RuntimeError(f"CLI returned the wrong cookie value: {cookies}")


def smoke_python(wheel: Path, database: Path, consumer: Path) -> None:
    venv = consumer / "python-venv"
    run([sys.executable, "-m", "venv", str(venv)], cwd=consumer)
    python = venv_python(venv)
    run(
        [
            str(python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-deps",
            "--no-index",
            str(wheel),
        ],
        cwd=consumer,
    )
    verifier = """
import json
import os
from pathlib import Path
import sys
import rookie_cookies

module = Path(rookie_cookies.__file__).resolve()
prefix = Path(sys.prefix).resolve()
if prefix not in module.parents:
    raise SystemExit(f"wheel module was not imported from the clean venv: {module}")
cookies = rookie_cookies.firefox_based(os.environ["ROOKIE_ARTIFACT_DB"], ["artifact.test"])
if len(cookies) != 1 or cookies[0]["name"] != "rookie_artifact" or cookies[0]["value"] != "installed-ok":
    raise SystemExit(f"wheel did not return the fixture: {json.dumps(cookies)}")
print(f"wheel: loaded {module}; rookie_artifact=installed-ok")
"""
    run(
        [str(python), "-I", "-c", verifier],
        cwd=consumer,
        env={
            **os.environ,
            "ROOKIE_ARTIFACT_DB": str(database),
            "PYTHONNOUSERSITE": "1",
        },
    )


def smoke_npm(
    root_tarball: Path,
    native_tarball: Path,
    native_package: str,
    native_entry: str,
    packaged_binary: bytes,
    database: Path,
    consumer: Path,
) -> None:
    node_consumer = consumer / "node-consumer"
    node_consumer.mkdir()
    (node_consumer / "package.json").write_text(
        json.dumps({"name": "rookie-artifact-consumer", "private": True}) + "\n",
        encoding="utf-8",
    )
    verifier_source = Path(__file__).with_name("node_consumer.cjs")
    shutil.copy2(verifier_source, node_consumer / "verify.cjs")
    npm = shutil.which("npm")
    node = shutil.which("node")
    if npm is None or node is None:
        raise RuntimeError("node and npm must be available")
    run(
        [
            npm,
            "install",
            "--ignore-scripts",
            "--no-audit",
            "--no-fund",
            "--no-package-lock",
            "--offline",
            str(native_tarball),
            str(root_tarball),
        ],
        cwd=node_consumer,
    )
    installed_binding = node_consumer / "node_modules" / native_package / native_entry
    if not installed_binding.is_file():
        raise RuntimeError(
            f"npm did not install the native binding: {installed_binding}"
        )
    if installed_binding.read_bytes() != packaged_binary:
        raise RuntimeError("installed native binding differs from the packed binding")
    run(
        [node, "verify.cjs", str(database), native_package],
        cwd=node_consumer,
    )


def main() -> int:
    args = parse_args()
    artifact_dir = args.artifact_dir.resolve()
    consumer = args.consumer_dir.resolve()
    repository = Path(__file__).resolve().parents[2]
    if repository == consumer or repository in consumer.parents:
        raise RuntimeError("consumer directory must be outside the repository")
    if consumer.exists():
        shutil.rmtree(consumer)
    consumer.mkdir(parents=True)

    provenance = validate_provenance(artifact_dir)
    npm_platform = str(provenance["npm_platform"])
    package_names = {
        "linux-x64-gnu": "rookie-cookies-linux-x64-gnu",
        "win32-x64-msvc": "rookie-cookies-win32-x64-msvc",
        "darwin-arm64": "rookie-cookies-darwin-arm64",
        "darwin-x64": "rookie-cookies-darwin-x64",
    }
    native_package = package_names.get(npm_platform)
    if native_package is None:
        raise RuntimeError(f"unsupported npm platform in provenance: {npm_platform}")

    cli = only_file(artifact_dir / "cli", "rookie-cookies-cli-*")
    wheel = only_file(artifact_dir / "python", "*.whl")
    npm_tarballs = sorted((artifact_dir / "npm").glob("*.tgz"))
    if len(npm_tarballs) != 2:
        raise RuntimeError(f"expected root + native npm tarballs, found {npm_tarballs}")
    native_tarball = next(path for path in npm_tarballs if native_package in path.name)
    root_tarball = next(path for path in npm_tarballs if path != native_tarball)

    validate_wheel(wheel)
    native_entry, packaged_binary = validate_npm_tarballs(
        root_tarball, native_tarball, native_package
    )
    database = consumer / "fixture with spaces 雪" / "cookies.sqlite"
    seed_firefox_database(database)

    installed_cli = consumer / "bin" / cli.name
    installed_cli.parent.mkdir()
    shutil.copy2(cli, installed_cli)
    smoke_cli(installed_cli, database, consumer)
    smoke_python(wheel, database, consumer)
    smoke_npm(
        root_tarball,
        native_tarball,
        native_package,
        native_entry,
        packaged_binary,
        database,
        consumer,
    )
    print("All downloaded release artifacts passed clean-consumer smoke tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
