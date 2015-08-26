# -*- coding: utf-8 -*-
from contextlib import ContextDecorator


class TempDir(ContextDecorator):
    def __init__(self, base_dir_path: str, suffix: str, directory_permissions: oct, do_restore_mtimes: bool):
        from tempfile import mkdtemp
        from os.path import normpath

        self.base_dir_path = normpath(base_dir_path)
        self.directory_permissions = directory_permissions
        self.suffix = suffix
        self.temp_base_dir_path = mkdtemp(suffix=suffix)
        self.do_restore_mtimes = do_restore_mtimes

    def _restore_mtimes(self):
        from hashlib import sha256
        from logging import debug
        from os import stat, walk, utime
        from os.path import exists, join, sep

        for dir_path, dir_names, file_names in walk(self.temp_base_dir_path):
            for file_name in file_names:
                current_file_path = join(dir_path, file_name)
                non_common_prefix, common_relative_dir_path = dir_path.rsplit(self.temp_base_dir_path)
                if non_common_prefix != '':
                    raise RuntimeError('temp_base_dir_path and/or base_dir_path are not absolute. '
                                       'Non common prefix: {non_common_prefix:s}'.format(
                        non_common_prefix=non_common_prefix))
                old_file_path = join(self.base_dir_path,
                                     common_relative_dir_path.lstrip(sep),
                                     file_name)

                if exists(old_file_path):
                    with open(current_file_path, mode='rb') as current_file:
                        current_hash = sha256()
                        current_hash.update(current_file.read())
                        with open(old_file_path, mode='rb') as previous_file:
                            old_hash = sha256()
                            old_hash.update(previous_file.read())

                    if current_hash.digest() == old_hash.digest():
                        debug("Restoring mtime of '{current_file_path:s}' "
                              "to that of '{old_file_path:s}' (equal hash values: {old_hash:s}).".
                              format(current_file_path=current_file_path, current_hash=current_hash.hexdigest(),
                                     old_hash=old_hash.hexdigest(), old_file_path=old_file_path))
                        old_stat_result = stat(old_file_path)
                        utime(current_file_path, (old_stat_result.st_atime, old_stat_result.st_mtime))
                    else:
                        debug("Not restoring mtime of '{current_file_path:s}' to that of '{old_file_path:s}' "
                              "(unequal hash values: {current_hash:s} {old_hash:s}).".
                              format(current_file_path=current_file_path, current_hash=current_hash.hexdigest(),
                                     old_hash=old_hash.hexdigest(), old_file_path=old_file_path))

    def __enter__(self):
        from logging import info

        info("Working in temporary base directory '{temp_base_dir_path:s}', to be moved to '{base_dir_path:s}'. ".
             format(temp_base_dir_path=self.temp_base_dir_path, base_dir_path=self.base_dir_path))
        return self

    def __exit__(self, *exc):
        from os import chmod
        from os.path import isdir
        from shutil import move
        from tempfile import mkdtemp
        from logging import warning

        if self.do_restore_mtimes:
            self._restore_mtimes()

        if isdir(self.base_dir_path):
            bak_base_dir_path = mkdtemp(suffix=self.suffix)
            warning("Trying to back up existent base directory '{base_dir_path:s}' to '{bak_base_dir_path:s}' ... ".
                    format(base_dir_path=self.base_dir_path, bak_base_dir_path=bak_base_dir_path))
            move(src=self.base_dir_path, dst=bak_base_dir_path)

        chmod(self.temp_base_dir_path, self.directory_permissions)  # TODO: use keyword arguments once Python >3.4
        move(src=self.temp_base_dir_path, dst=self.base_dir_path)
