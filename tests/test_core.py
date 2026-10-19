import os
import stat
import tempfile
import unittest

import tiny_permission_mask as tpm
from tiny_permission_mask import Mask, check_path, check_stat


class TestMaskConstruction(unittest.TestCase):
    def test_single_flag(self):
        m = Mask(Mask.GROUP_WRITE)
        self.assertEqual(m.required_bits, stat.S_IWGRP)

    def test_multiple_flags_combined(self):
        m = Mask(Mask.GROUP_WRITE, Mask.OTHER_READ)
        self.assertEqual(m.required_bits, stat.S_IWGRP | stat.S_IROTH)

    def test_repeated_flags_idempotent(self):
        m = Mask(Mask.OTHER_READ, Mask.OTHER_READ)
        self.assertEqual(m.required_bits, stat.S_IROTH)

    def test_no_flags_means_empty_mask(self):
        m = Mask()
        self.assertEqual(m.required_bits, 0)

    def test_negative_flag_rejected(self):
        with self.assertRaises(ValueError):
            Mask(-1)

    def test_non_int_flag_rejected(self):
        with self.assertRaises(TypeError):
            Mask(0o020, "GROUP_WRITE")  # type: ignore[arg-type]

    def test_repr(self):
        m = Mask(Mask.GROUP_WRITE)
        self.assertIn("required_bits=0o20", repr(m))


class TestCheckStat(unittest.TestCase):
    def _stat_with_mode(self, mode):
        """
        Build a real os.stat_result with a controlled st_mode.

        Using a genuine os.stat_result (not a stub) lets the isinstance
        check inside check_stat succeed naturally. st_mode is the only
        field the library reads, so the rest are filled with zeros.
        """
        st = os.stat_result((mode, 0, 0, 0, 0, 0, 0, 0, 0, 0))
        return st

    def test_required_bit_present(self):
        st = self._stat_with_mode(0o640)
        self.assertTrue(check_stat(st, Mask(Mask.GROUP_READ)))

    def test_required_bit_absent(self):
        st = self._stat_with_mode(0o600)
        self.assertFalse(check_stat(st, Mask(Mask.GROUP_READ)))

    def test_subset_is_satisfied(self):
        st = self._stat_with_mode(0o666)
        m = Mask(Mask.GROUP_WRITE, Mask.OTHER_READ)
        self.assertTrue(check_stat(st, m))

    def test_one_of_two_required_absent(self):
        st = self._stat_with_mode(0o620)
        m = Mask(Mask.GROUP_WRITE, Mask.OTHER_READ)
        self.assertFalse(check_stat(st, m))

    def test_empty_mask_satisfied_by_anything(self):
        st = self._stat_with_mode(0o000)
        self.assertTrue(check_stat(st, Mask()))

    def test_special_bit_setuid(self):
        st = self._stat_with_mode(0o4755)
        self.assertTrue(check_stat(st, Mask(Mask.SETUID)))

    def test_special_bit_absent(self):
        st = self._stat_with_mode(0o0755)
        self.assertFalse(check_stat(st, Mask(Mask.SETUID)))

    def test_file_type_bits_ignored(self):
        # A regular file (0o100000) and a directory (0o040000) with the
        # same permission bits should both satisfy a permission-only mask.
        regular = self._stat_with_mode(stat.S_IFREG | 0o640)
        directory = self._stat_with_mode(stat.S_IFDIR | 0o640)
        m = Mask(Mask.GROUP_READ)
        self.assertTrue(check_stat(regular, m))
        self.assertTrue(check_stat(directory, m))

    def test_non_stat_result_rejected(self):
        with self.assertRaises(TypeError):
            check_stat("not-a-stat", Mask())  # type: ignore[arg-type]

    def test_non_mask_rejected(self):
        st = self._stat_with_mode(0o640)
        with self.assertRaises(TypeError):
            check_stat(st, 0o020)  # type: ignore[arg-type]


class TestCheckPath(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _make_file(self, mode):
        p = os.path.join(self.tmp.name, "f")
        with open(p, "w") as fh:
            fh.write("x")
        os.chmod(p, mode)
        return p

    def _make_dir(self, mode):
        p = os.path.join(self.tmp.name, "d")
        os.mkdir(p)
        os.chmod(p, mode)
        return p

    def test_file_group_writable_satisfied(self):
        p = self._make_file(0o660)
        self.assertTrue(check_path(p, Mask(Mask.GROUP_WRITE)))

    def test_file_group_writable_not_satisfied(self):
        p = self._make_file(0o640)
        self.assertFalse(check_path(p, Mask(Mask.GROUP_WRITE)))

    def test_directory_world_readable(self):
        p = self._make_dir(0o755)
        self.assertTrue(check_path(p, Mask(Mask.OTHER_READ)))

    def test_directory_not_world_readable(self):
        p = self._make_dir(0o750)
        self.assertFalse(check_path(p, Mask(Mask.OTHER_READ)))

    def test_non_string_path_rejected(self):
        with self.assertRaises(TypeError):
            check_path(123, Mask())  # type: ignore[arg-type]

    def test_non_mask_rejected(self):
        p = self._make_file(0o640)
        with self.assertRaises(TypeError):
            check_path(p, 0o020)  # type: ignore[arg-type]

    def test_nonexistent_path_raises(self):
        missing = os.path.join(self.tmp.name, "does-not-exist")
        with self.assertRaises(FileNotFoundError):
            check_path(missing, Mask(Mask.OTHER_READ))


class TestPackageExports(unittest.TestCase):
    def test_exports_present(self):
        self.assertTrue(hasattr(tpm, "Mask"))
        self.assertTrue(hasattr(tpm, "check_path"))
        self.assertTrue(hasattr(tpm, "check_stat"))

    def test_mask_constants_match_stat(self):
        self.assertEqual(Mask.GROUP_WRITE, stat.S_IWGRP)
        self.assertEqual(Mask.OTHER_READ, stat.S_IROTH)
        self.assertEqual(Mask.SETUID, stat.S_ISUID)
        self.assertEqual(Mask.STICKY, stat.S_ISVTX)


if __name__ == "__main__":
    unittest.main()
