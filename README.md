# tiny-permission-mask

Checks whether a path's permission bits satisfy a required mask (e.g. group-writable, world-readable).

```python
import os
import tempfile
from tiny_permission_mask import Mask, check_stat

# Create a temporary file and set it group-writable and world-readable.
with tempfile.NamedTemporaryFile(delete=False) as fh:
    path = fh.name
os.chmod(path, 0o646)

st = os.stat(path)

# Require that a path is group-writable AND world-readable.
mask = Mask(Mask.GROUP_WRITE, Mask.OTHER_READ)

if check_stat(st, mask):
    print("permissions are sufficient")
else:
    print("permissions are too restrictive")
```

`check_stat` takes an `os.stat_result` directly, which is useful when you already have a stat handle or want to test with synthetic data:

```python
import os
import tempfile
from tiny_permission_mask import Mask, check_stat

with tempfile.NamedTemporaryFile(delete=False) as fh:
    path = fh.name
os.chmod(path, 0o644)

st = os.stat(path)
print(check_stat(st, Mask(Mask.OTHER_READ)))
```

## Why this exists

A common ops task is verifying that a file or directory has *at least* the permissions a service expects — a log directory that must be group-writable, a secret that must *not* be world-readable. Doing this with raw octal literals is error-prone: 0o020 and 0o002 differ by one zero and mean completely different things. This library gives those bits names and performs a subset check rather than an exact equality check, because the question is almost always "are these rights present?", not "are these the only rights present?".

## Edge cases

- **Subset semantics.** A mode of 0o666 satisfies a mask that only requires group-writable. If you need to assert that no *extra* bits are set (e.g. rejecting world-writable), build a mask from all the bits you want to forbid and assert that `check_stat` is False.
- **File-type bits are ignored.** Only the permission and special bits (0o7777) of `st_mode` participate. A regular file and a directory with the same permission bits behave identically.
- **Symlinks.** `check_path` follows symlinks by default (uses `os.stat`). Pass `follow_symlinks=False` to check the link itself with `os.lstat`.
- **Special bits.** `SETUID`, `SETGID`, and `STICKY` are available as mask flags for callers that need to verify those.
