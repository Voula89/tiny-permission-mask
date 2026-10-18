from __future__ import annotations

import os
import stat
from dataclasses import dataclass

__all__ = ["Mask", "check_path", "check_stat"]


class Mask:
    """
    Represents a required permission mask (a subset of POSIX mode bits).

    The mask is built from symbolic constants (GROUP_WRITE, OTHER_READ, ...).
    A path is considered to satisfy the mask when, for every required bit,
    the path's actual permission bits also have that bit set.

    Design decision — subset, not exact match:
        Permission checkers almost always want "does the path have at least
        these rights?", not "does the path have exactly these rights and no
        others?". A directory that is world-readable and world-executable
        should satisfy a mask that merely requires world-readable. Treating
        the mask as a subset avoids false negatives on sensible, slightly
        broader permissions.

    Design decision — symbolic flags instead of raw octal:
        Callers could pass 0o020 for group-writable, but that is easy to
        misalign (0o002 is world-writable, a common off-by-one). Named
        flags make the call site read like a sentence and reduce the chance
        of quietly checking the wrong bit.
    """

    GROUP_READ = stat.S_IRGRP
    GROUP_WRITE = stat.S_IWGRP
    GROUP_EXECUTE = stat.S_IXGRP
    OTHER_READ = stat.S_IROTH
    OTHER_WRITE = stat.S_IWOTH
    OTHER_EXECUTE = stat.S_IXOTH
    USER_READ = stat.S_IRUSR
    USER_WRITE = stat.S_IWUSR
    USER_EXECUTE = stat.S_IXUSR
    SETUID = stat.S_ISUID
    SETGID = stat.S_ISGID
    STICKY = stat.S_ISVTX

    def __init__(self, *flags: int) -> None:
        self._required = 0
        for f in flags:
            if not isinstance(f, int):
                raise TypeError(f"flag must be int, got {type(f).__name__}")
            if f < 0:
                raise ValueError(f"flag must be non-negative, got {f}")
            self._required |= f

    @property
    def required_bits(self) -> int:
        """The combined integer of all required permission bits."""
        return self._required

    def __repr__(self) -> str:
        return f"Mask(required_bits={self._required:#o})"


def check_stat(path_stat: os.stat_result, mask: Mask) -> bool:
    """
    Return True when every required bit in *mask* is set on *path_stat*.

    Uses st_mode directly so callers can inspect an already-obtained stat
    result (or a fake one in tests) without a second filesystem round-trip.
    Only the permission and special bits are considered; the file-type bits
    in st_mode are irrelevant to this check and are masked out.
    """
    if not isinstance(path_stat, os.stat_result):
        raise TypeError(
            f"path_stat must be os.stat_result, got {type(path_stat).__name__}"
        )
    if not isinstance(mask, Mask):
        raise TypeError(f"mask must be Mask, got {type(mask).__name__}")

    actual = path_stat.st_mode & 0o7777  # permission + special bits only
    required = mask.required_bits
    return (actual & required) == required


def check_path(path: str, mask: Mask, *, follow_symlinks: bool = True) -> bool:
    """
    Return True when the permission bits of *path* satisfy *mask*.

    By default symlinks are followed (os.stat). When follow_symlinks is
    False, os.lstat is used so the link's own mode is checked rather than
    the target's. The symlink-following decision is left to the caller
    because the correct choice depends on the security question being
    asked.
    """
    if not isinstance(path, str):
        raise TypeError(f"path must be str, got {type(path).__name__}")
    if not isinstance(mask, Mask):
        raise TypeError(f"mask must be Mask, got {type(mask).__name__}")

    st = os.stat(path) if follow_symlinks else os.lstat(path)
    return check_stat(st, mask)
