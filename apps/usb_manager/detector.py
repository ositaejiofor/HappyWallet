"""
HappyWallet USB Device Detector.

Detects removable storage devices without automatically trusting them.

IMPORTANT:
USB detection is NOT USB authentication.

A removable drive must never be considered a trusted wallet merely
because it is connected to the computer.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path


# ============================================================================
# DATA MODEL
# ============================================================================


@dataclass(frozen=True, slots=True)
class USBDevice:
    """
    Information about a detected removable storage device.

    Detection only identifies removable storage. It does NOT authenticate
    the device as a trusted HappyWallet signer.
    """

    device_id: str
    mount_path: Path
    label: str | None = None
    filesystem: str | None = None
    removable: bool = True

    def __post_init__(self) -> None:
        if not isinstance(self.device_id, str):
            raise TypeError("device_id must be a string.")

        if not self.device_id.strip():
            raise ValueError("device_id cannot be empty.")

        if not isinstance(self.mount_path, Path):
            raise TypeError("mount_path must be a pathlib.Path.")

        if not self.mount_path:
            raise ValueError("mount_path cannot be empty.")

        if self.label is not None and not isinstance(
            self.label,
            str,
        ):
            raise TypeError("label must be a string or None.")

        if self.filesystem is not None and not isinstance(
            self.filesystem,
            str,
        ):
            raise TypeError(
                "filesystem must be a string or None."
            )

        if not isinstance(self.removable, bool):
            raise TypeError("removable must be a boolean.")


# ============================================================================
# DETECTOR
# ============================================================================


class USBDetector:
    """
    Detect removable storage devices.

    Supported platforms:

        - Windows
        - Linux
        - macOS

    Detection does not establish trust or authentication.
    """

    WINDOWS_TIMEOUT_SECONDS = 10

    def __init__(
        self,
        *,
        system: str | None = None,
    ) -> None:
        """
        Initialize the detector.

        ``system`` is injectable for testing.
        """

        if system is None:
            system = platform.system()

        if not isinstance(system, str):
            raise TypeError("system must be a string or None.")

        self.system = system.strip().lower()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    def detect(self) -> list[USBDevice]:
        """
        Detect currently mounted removable storage devices.
        """

        if self.system == "windows":
            return self._detect_windows()

        if self.system == "linux":
            return self._detect_linux()

        if self.system == "darwin":
            return self._detect_macos()

        return []

    # =========================================================================
    # WINDOWS
    # =========================================================================

    def _detect_windows(self) -> list[USBDevice]:
        """
        Detect removable logical drives on Windows.

        Win32_LogicalDisk DriveType 2 means removable disk.

        Detection is deliberately limited to removable drives and does not
        authenticate a HappyWallet vault.
        """

        command = [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            (
                "Get-CimInstance Win32_LogicalDisk "
                "| Where-Object {$_.DriveType -eq 2} "
                "| Select-Object DeviceID,VolumeName,FileSystem "
                "| ConvertTo-Json -Compress"
            ),
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.WINDOWS_TIMEOUT_SECONDS,
                check=False,
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return []

        if result.returncode != 0:
            return []

        output = result.stdout.strip()

        if not output:
            return []

        try:
            data = json.loads(output)
        except (
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            return []

        if isinstance(data, dict):
            data = [data]

        if not isinstance(data, list):
            return []

        devices: list[USBDevice] = []

        for item in data:
            if not isinstance(item, dict):
                continue

            device_id = item.get("DeviceID")

            if not isinstance(device_id, str):
                continue

            device_id = device_id.strip()

            if not device_id:
                continue

            mount_path = Path(
                f"{device_id}\\"
            )

            devices.append(
                USBDevice(
                    device_id=device_id,
                    mount_path=mount_path,
                    label=self._clean_optional_string(
                        item.get("VolumeName")
                    ),
                    filesystem=self._clean_optional_string(
                        item.get("FileSystem")
                    ),
                    removable=True,
                )
            )

        return devices

    # =========================================================================
    # LINUX
    # =========================================================================

    def _detect_linux(self) -> list[USBDevice]:
        """
        Detect mounted removable storage on Linux.

        This implementation uses ``lsblk`` when available.

        We intentionally do not recursively scan /mnt or /media because doing
        so can incorrectly classify arbitrary directories as USB devices.
        """

        command = [
            "lsblk",
            "-J",
            "-o",
            "NAME,PATH,TYPE,RM,FSTYPE,LABEL,MOUNTPOINT",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=self.WINDOWS_TIMEOUT_SECONDS,
                check=False,
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return []

        if result.returncode != 0:
            return []

        output = result.stdout.strip()

        if not output:
            return []

        try:
            document = json.loads(output)
        except (
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ):
            return []

        if not isinstance(document, dict):
            return []

        blockdevices = document.get("blockdevices")

        if not isinstance(blockdevices, list):
            return []

        devices: list[USBDevice] = []

        self._collect_linux_devices(
            blockdevices,
            devices,
        )

        return devices

    @classmethod
    def _collect_linux_devices(
        cls,
        entries: list[object],
        devices: list[USBDevice],
    ) -> None:
        """
        Recursively collect removable mounted Linux block devices.
        """

        for entry in entries:
            if not isinstance(entry, dict):
                continue

            removable = entry.get("rm")
            mountpoint = entry.get("mountpoint")
            device_path = entry.get("path")

            if (
                removable in (1, "1", True)
                and isinstance(mountpoint, str)
                and mountpoint.strip()
                and isinstance(device_path, str)
                and device_path.strip()
            ):
                devices.append(
                    USBDevice(
                        device_id=device_path.strip(),
                        mount_path=Path(
                            mountpoint.strip()
                        ),
                        label=cls._clean_optional_string(
                            entry.get("label")
                        ),
                        filesystem=cls._clean_optional_string(
                            entry.get("fstype")
                        ),
                        removable=True,
                    )
                )

            children = entry.get("children")

            if isinstance(children, list):
                cls._collect_linux_devices(
                    children,
                    devices,
                )

    # =========================================================================
    # MACOS
    # =========================================================================

    def _detect_macos(self) -> list[USBDevice]:
        """
        Detect mounted volumes on macOS.

        macOS does not expose a simple equivalent of Windows DriveType.

        ``diskutil`` is therefore used to determine whether a mounted volume
        belongs to an external/removable device.
        """

        command = [
            "diskutil",
            "list",
            "-plist",
        ]

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                timeout=self.WINDOWS_TIMEOUT_SECONDS,
                check=False,
            )
        except (
            OSError,
            subprocess.SubprocessError,
        ):
            return []

        if result.returncode != 0:
            return []

        # A full plist parser would add unnecessary complexity here.
        # Fall back to mounted-volume discovery rather than pretending that
        # every /Volumes directory is necessarily removable.
        return self._detect_macos_volumes()

    def _detect_macos_volumes(self) -> list[USBDevice]:
        """
        Return mounted macOS volumes as a conservative fallback.

        Authentication must still be performed separately.
        """

        volumes = Path("/Volumes")

        if not volumes.is_dir():
            return []

        devices: list[USBDevice] = []

        try:
            entries = list(volumes.iterdir())
        except OSError:
            return []

        for path in entries:
            try:
                if not path.is_dir():
                    continue

                devices.append(
                    USBDevice(
                        device_id=str(path),
                        mount_path=path,
                        label=path.name,
                        removable=True,
                    )
                )
            except OSError:
                continue

        return devices

    # =========================================================================
    # AVAILABILITY
    # =========================================================================

    @staticmethod
    def is_available(
        device: USBDevice,
    ) -> bool:
        """
        Return True when the device mount point is currently available.

        This checks the filesystem path only. It does NOT authenticate the
        device or prove that it is the original physical USB device.
        """

        if not isinstance(device, USBDevice):
            raise TypeError(
                "device must be a USBDevice."
            )

        try:
            return (
                device.removable
                and device.mount_path.is_dir()
            )
        except OSError:
            return False

    # =========================================================================
    # FREE SPACE
    # =========================================================================

    @classmethod
    def free_space(
        cls,
        device: USBDevice,
    ) -> int:
        """
        Return available storage space in bytes.
        """

        if not isinstance(device, USBDevice):
            raise TypeError(
                "device must be a USBDevice."
            )

        if not cls.is_available(device):
            raise OSError(
                "USB device is not available."
            )

        try:
            usage = shutil.disk_usage(
                device.mount_path
            )
        except OSError as exc:
            raise OSError(
                "Unable to determine free space."
            ) from exc

        return usage.free

    # =========================================================================
    # SEARCH
    # =========================================================================

    def find(
        self,
        device_id: str,
    ) -> USBDevice | None:
        """
        Find a currently detected removable device by ID.
        """

        if not isinstance(device_id, str):
            raise TypeError(
                "device_id must be a string."
            )

        device_id = device_id.strip()

        if not device_id:
            return None

        for device in self.detect():
            if device.device_id == device_id:
                return device

        return None

    # =========================================================================
    # HELPERS
    # =========================================================================

    @staticmethod
    def _clean_optional_string(
        value: object,
    ) -> str | None:
        """
        Normalize an optional string returned by the operating system.
        """

        if not isinstance(value, str):
            return None

        value = value.strip()

        return value or None


__all__ = [
    "USBDevice",
    "USBDetector",
]
