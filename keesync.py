#!/usr/bin/env python3

import os
import re
import json
import time
import typing
import logging
import hashlib
import dropbox
import argparse
import requests

from dropbox import files as dbx_files
from dropbox.files import FileMetadata
from dropbox.exceptions import ApiError
from dropbox import DropboxOAuth2FlowNoRedirect

from datetime import datetime

VERSION = '0.1'

logger = logging.getLogger(__name__)
handler = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger.addHandler(handler)


class ExtendedFileMetadata:
    def __init__(self, meta: FileMetadata):
        self._meta = meta

    def __getattr__(self, item):
        try:
            return self._meta.__getattribute__(item)
        except AttributeError as err:
            raise AttributeError('\'{}\' object has no attribute \'{}\''.format(self._meta.__class__.__name__,
                                                                                item)) from None

    def to_json(self):
        return json.dumps({
            'content_hash': self.content_hash,
            'rev': self.rev
        })

    def save(self, path):
        with open(path, 'w') as f_dsc:
            f_dsc.write(self.to_json())
            f_dsc.close()


class Application:
    def __init__(self, app_key, db_path):
        self._app_key = app_key
        self._db_path = db_path
        self._dbx: dropbox.Dropbox = self._get_dropbox(self._token_path)

    def sync(self):
        if self._does_local_db_exists() and self._does_remote_db_exists():
            if self._check_file_is_changed():
                mtime = os.path.getmtime(self._db_path)
                local_modified = datetime(*time.gmtime(mtime)[:6])
                remote_modified = self._get_db_path_meta().client_modified
                if local_modified > remote_modified:
                    ext_meta = self._upload_db(mode='overwrite')
                    ext_meta.save(self._meta_path)
                else:
                    ext_meta = self._download_db_to_origin()
                    ext_meta.save(self._meta_path)
        elif self._does_local_db_exists() and not self._does_remote_db_exists():
            ext_meta = self._upload_db(mode='add')
            ext_meta.save(self._meta_path)
        elif not self._does_local_db_exists() and self._does_remote_db_exists():
            ext_meta = self._download_db_to_origin()
            ext_meta.save(self._meta_path)
        else:
            logger.warning('Nothing to sync!')

    def _does_local_db_exists(self) -> bool:
        return os.path.exists(self._db_path)

    def _does_remote_db_exists(self) -> bool:
        return self._does_remote_file_exists(self._remote_db_path)

    def _does_remote_file_exists(self, path: str) -> bool:
        try:
            self._get_remote_path_meta(path)
            return True
        except ApiError as err:
            if err.error.is_path:
                path = err.error.get_path()
                if path.is_not_found():
                    return False
            raise err

    def _check_file_is_changed(self) -> bool:
        saved_meta = self._get_saved_file_meta()
        remote_meta = self._get_db_path_meta()

        saved_hash = saved_meta.get('content_hash', '')
        remote_hash = remote_meta.content_hash
        changed = saved_hash != remote_hash or self._calculate_sha256(self._db_path) != remote_hash
        if changed:
            logger.info('Changes detected')
        else:
            logger.debug('Files were not changed')
        return changed

    def _get_saved_file_meta(self) -> dict:
        if os.path.isfile(self._meta_path):
            content = self._read_from_file(self._meta_path)
            return json.loads(content)
        return {}

    def _get_db_path_meta(self) -> FileMetadata:
        return self._get_remote_path_meta(self._remote_db_path)

    def _get_remote_path_meta(self, path: str) -> FileMetadata:
        return self._dbx.files_get_metadata(path)

    def _upload_db(self, meta: typing.Union[FileMetadata, ExtendedFileMetadata, None] = None,
                   mode: str = 'overwrite') -> ExtendedFileMetadata:
        logger.info('Uploading to remote storage')
        content = self._read_from_file(self._db_path)
        mtime = os.path.getmtime(self._db_path)
        client_modified = datetime(*time.gmtime(mtime)[:6])
        if mode == 'add':
            mode = dbx_files.WriteMode.add
        elif mode == 'overwrite':
            mode = dbx_files.WriteMode.overwrite
        elif mode == 'update':
            mode = dbx_files.WriteMode.update(meta.rev)
        else:
            raise AssertionError('Unknown uploading mode.')

        meta = self._dbx.files_upload(content,
                                      self._remote_db_path,
                                      mode=mode,
                                      autorename=True,
                                      client_modified=client_modified,
                                      mute=False,
                                      property_groups=None,
                                      strict_conflict=False)
        return ExtendedFileMetadata(meta)

    def _download_db_to_origin(self) -> ExtendedFileMetadata:
        logger.info('Downloading from remote storage')
        meta = self._dbx.files_download_to_file(self._db_path, self._remote_db_path)
        return ExtendedFileMetadata(meta)

    def _get_refresh_token(self, token_path):
        refresh_token = ''
        if os.path.exists(token_path):
            with open(token_path, 'r') as f_dsc:
                refresh_token = f_dsc.read()

        if not refresh_token:
            auth_flow = DropboxOAuth2FlowNoRedirect(self._app_key, use_pkce=True, token_access_type='offline')

            authorize_url = auth_flow.start()
            print("1. Go to: " + authorize_url)
            print("2. Click \"Allow\" (you might have to log in first).")
            print("3. Copy the authorization code.")
            auth_code = input("Enter the authorization code here: ").strip()

            try:
                oauth_result = auth_flow.finish(auth_code)
            except Exception:
                logger.exception('Could not get token!')
            else:
                refresh_token = oauth_result.refresh_token
        return refresh_token

    def _get_dropbox(self, token_path) -> dropbox.Dropbox:
        token = self._get_refresh_token(token_path)
        self._save_token(token)
        return dropbox.Dropbox(oauth2_refresh_token=token, app_key=self._app_key)

    def _save_token(self, token):
        self._write_to_file(self._token_path, token)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._dbx.__exit__(exc_type, exc_val, exc_tb)

    @staticmethod
    def _calculate_sha256(local_path):
        with open(local_path, 'rb') as fdsc:
            binary = b''
            while True:
                chunk = fdsc.read(4 * 1024 * 1024)
                if not chunk:
                    break
                binary += hashlib.sha256(chunk).digest()
            hash = hashlib.sha256(binary).hexdigest()
        return hash

    @staticmethod
    def _write_to_file(path, content):
        with open(path, 'w') as fdsc:
            fdsc.write(content)

    @staticmethod
    def _read_from_file(path):
        with open(path, 'rb') as fdsc:
            content = fdsc.read()
        return content

    @property
    def _tmp_db_path(self):
        return 'tmp_' + self._db_path

    @property
    def _token_path(self):
        return '.token'

    @property
    def _remote_db_path(self):
        return os.path.join('/', os.path.basename(self._db_path))

    @property
    def _meta_path(self):
        return '.meta'

    @property
    def _conflict_dir(self):
        return '/conflicts'

    @property
    def _conflict_regex(self):
        name, extension = os.path.splitext(os.path.basename(self._remote_db_path))
        return re.compile(name + r'.*conflicted copy\)' + extension)


def parse_args():
    arg_parser = argparse.ArgumentParser(prog='keesync', description='Synchronize keepass database through dropbox.')
    arg_parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + VERSION)
    arg_parser.add_argument('-a', '--app', default='',  help='application key')
    arg_parser.add_argument('-p', '--path', required=True, help='path to keepass database')
    arg_parser.add_argument('-s', '--sleep', default=1, type=int, help='time interval in seconds before '
                                                                       'he next iteration of synchronization')
    arg_parser.add_argument('-l', '--log', default='info',
                            choices=['debug', 'info', 'warning', 'error', 'critical'], help='logging level')
    arg_parser.add_argument('-i', '--init', action='store_true', help='initialize application - generate refresh token')
    args = arg_parser.parse_args()

    if not os.path.exists(os.path.dirname(args.path) or './'):
        print('File "{}" does not exist.'.format(args.path))
        return

    if not args.sleep > 0:
        print('Interval must be greater than 0.')
        return

    return args


def set_log_level(log_name, level: str):
    levels = {
        'critical': logging.CRITICAL,
        'error': logging.ERROR,
        'warning': logging.WARNING,
        'info': logging.INFO,
        'debug': logging.DEBUG}
    logger_instance = logging.getLogger(log_name)
    logger_instance.setLevel(levels[level])


def read_app_key_from_env() -> str:
    return os.environ.get('KEESYNC_APP_KEY', '')

def main():
    args = parse_args()
    if not args:
        return

    set_log_level(__name__, args.log)
    app_key = args.app if args.app else read_app_key_from_env()
    if not app_key:
        logger.warning('Application key is required')
        exit(0)

    try:
        with Application(app_key, args.path) as app:
            if args.init:
                return
            while True:
                try:
                    app.sync()
                except requests.exceptions.HTTPError as err:
                    logger.warning('HTTP error occurred {}'.format(err))
                time.sleep(args.sleep)
    except KeyboardInterrupt:
        logger.info('Exit app.')
    except Exception:
        logger.exception('Undefined err occurred.')


if __name__ == '__main__':
    main()
