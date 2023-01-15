#!/usr/bin/env python3

from avbroot import external

import argparse
import os
import shutil
import tempfile
import zipfile

import avbtool

from avbroot import boot
from avbroot import openssl
from avbroot import ota
from avbroot import util
from avbroot import vbmeta


PATH_METADATA_PB = 'META-INF/com/android/metadata.pb'
PATH_PAYLOAD = 'payload.bin'
PATH_PROPERTIES = 'payload_properties.txt'
SKIP_PATHS = (
    PATH_METADATA_PB,
    'META-INF/com/android/metadata',
    'META-INF/com/android/otacert',
)


def print_status(*args, **kwargs):
    print('\x1b[1m*****', *args, '*****\x1b[0m', **kwargs)


def patch_ota_payload(f_in, boot_out, vbmeta_out, file_size, custom_boot, privkey_avb):
    with tempfile.TemporaryDirectory() as temp_dir:
        extract_dir = os.path.join(temp_dir, 'extract')
        os.mkdir(extract_dir)

        version, manifest, blob_offset = ota.parse_payload(f_in)

        print_status('Extracting vbmeta, boot from the payload')
        ota.extract_images(f_in, manifest, blob_offset, extract_dir, ['vbmeta', 'boot'])

        avb = avbtool.Avb()

        print_status('Patching boot image')
        boot.patch_boot(
            avb,
            os.path.join(extract_dir, 'boot.img'),
            custom_boot,
            boot_out,
            privkey_avb,
            True,
        )

        print_status('Building new root vbmeta image')
        vbmeta.patch_vbmeta_root(
            avb,
            [boot_out],
            os.path.join(extract_dir, 'vbmeta.img'),
            vbmeta_out,
            privkey_avb,
            manifest.block_size,
        )


def patch_ota_zip(f_zip_in, boot_out, vbmeta_out, custom_boot, privkey_avb):
    with (
        zipfile.ZipFile(f_zip_in, 'r') as z_in,
    ):
        infolist = z_in.infolist()
        missing = {PATH_METADATA_PB, PATH_PAYLOAD, PATH_PROPERTIES}
        i_payload = -1
        i_properties = -1

        for i, info in enumerate(infolist):
            if info.filename in missing:
                missing.remove(info.filename)

            if info.filename == PATH_PAYLOAD:
                i_payload = i
            elif info.filename == PATH_PROPERTIES:
                i_properties = i

            if not missing and i_payload >= 0 and i_properties >= 0:
                break

        if missing:
            raise Exception(f'Missing files in zip: {missing}')

        # Ensure payload is processed before properties
        if i_payload > i_properties:
            infolist[i_payload], infolist[i_properties] = \
                infolist[i_properties], infolist[i_payload]

        properties = None
        metadata = None

        for info in z_in.infolist():
            # The existing metadata is needed to generate a new signed zip
            if info.filename == PATH_METADATA_PB:
                with z_in.open(info, 'r') as f_in:
                    metadata = f_in.read()

            # Skip files that are created during zip signing
            if info.filename in SKIP_PATHS:
                print_status('Skipping', info.filename)
                continue

            # Copy other files, patching if needed
            with (
                z_in.open(info, 'r') as f_in,
            ):
                if info.filename == PATH_PAYLOAD:
                    print_status('Patching', info.filename)

                    if info.compress_type != zipfile.ZIP_STORED:
                        raise Exception(f'{info.filename} is not stored uncompressed')

                    properties = patch_ota_payload(
                        f_in,
                        boot_out,
                        vbmeta_out,
                        info.file_size,
                        custom_boot,
                        privkey_avb,
                    )

        return metadata


def patch_subcommand(args):
    # Decrypt keys to temp directory in RAM
    with tempfile.TemporaryDirectory(dir='/dev/shm') as key_dir:
        print_status('Decrypting keys to RAM-based temporary directory')

        # avbtool requires a PEM-encoded private key
        dec_privkey_avb = os.path.join(key_dir, 'avb.key')
        openssl.decrypt_key(args.privkey_avb, dec_privkey_avb)

        patch_ota_zip(
            args.input,
            args.output_boot,
            args.output_vbmeta,
            args.custom_boot,
            dec_privkey_avb,
        )


def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest='subcommand', required=True,
                                       help='Subcommands')

    patch = subparsers.add_parser('patch', help='Patch a full OTA zip')

    patch.add_argument('--input', required=True,
                       help='Path to original raw payload or OTA zip')
    patch.add_argument('--custom_boot', required=True,
                       help='Path to custom boot')
    patch.add_argument('--output_boot', required=True,
                       help='Path to patched boot')
    patch.add_argument('--output_vbmeta', required=True,
                       help='Path to patched vbmeta')
    patch.add_argument('--privkey-avb', required=True,
                       help='Private key for signing root vbmeta image')

    return parser.parse_args()


def main():
    args = parse_args()

    if args.subcommand == 'patch':
        patch_subcommand(args)
    else:
        raise NotImplementedError()


if __name__ == '__main__':
    main()
