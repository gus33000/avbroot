import shutil

import avbtool

from . import util
from . import vbmeta



def patch_boot(avb, input_path, custom_input_path, output_path, key, only_if_previously_signed):
    '''
    Resign the image using the provided private key.
    '''

    image = avbtool.ImageHandler(input_path, read_only=True)
    footer, header, descriptors, image_size = avb._parse_image(image)

    have_key_old = not not header.public_key_size
    if not have_key_old and only_if_previously_signed:
        key = None

    have_key_new = not not key

    if have_key_old != have_key_new:
        raise Exception('Key presence does not match: %s (old) != %s (new)' %
                        (have_key_old, have_key_new))

    hash = None
    new_descriptors = []

    for d in descriptors:
        if isinstance(d, avbtool.AvbHashDescriptor):
            if hash is not None:
                raise Exception(f'Expected only one hash descriptor')
            hash = d
        else:
            new_descriptors.append(d)

    if hash is None:
        raise Exception(f'No hash descriptor found')

    algorithm_name = avbtool.lookup_algorithm_by_type(header.algorithm_type)[0]

    # Pixel 7's init_boot image is originally signed by a 2048-bit RSA key, but
    # avbroot expects RSA 4096 keys
    if algorithm_name == 'SHA256_RSA2048':
        algorithm_name = 'SHA256_RSA4096'

    with util.open_output_file(output_path) as f:
        shutil.copyfile(custom_input_path, f.name)

        # Strip the vbmeta footer from the boot image
        # avb.erase_footer(f.name, False)

        # Sign the new boot image
        with vbmeta.smuggle_descriptors():
            avb.add_hash_footer(
                image_filename = f.name,
                partition_size = image_size,
                dynamic_partition_size = False,
                partition_name = hash.partition_name,
                hash_algorithm = hash.hash_algorithm,
                salt = hash.salt.hex(),
                chain_partitions = None,
                algorithm_name = algorithm_name,
                key_path = key,
                public_key_metadata_path = None,
                rollback_index = header.rollback_index,
                flags = header.flags,
                rollback_index_location = header.rollback_index_location,
                props = None,
                props_from_file = None,
                kernel_cmdlines = new_descriptors,
                setup_rootfs_from_kernel = None,
                include_descriptors_from_image = None,
                calc_max_image_size = False,
                signing_helper = None,
                signing_helper_with_files = None,
                release_string = header.release_string,
                append_to_release_string = None,
                output_vbmeta_image = None,
                do_not_append_vbmeta_image = False,
                print_required_libavb_version = False,
                use_persistent_digest = False,
                do_not_use_ab = False,
            )
