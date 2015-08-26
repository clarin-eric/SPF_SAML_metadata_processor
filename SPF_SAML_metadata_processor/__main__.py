#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from stat import S_ISGID, S_IRUSR, S_IWUSR, S_IXUSR, S_IRGRP, S_IXGRP, S_IROTH, S_IXOTH

from SPF_SAML_metadata_processor.tempdir import TempDir

# TODO: Python 3.3+
# from os import open
# opener = open(mode=0o777)

CLARIN_IDP_FED_NAME = 'CLARIN IdP'
CLARIN_IDP_XML_FILE_NAME = CLARIN_IDP_FED_NAME + '.xml'

DIRECTORY_PERMISSIONS = S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH

NAMESPACE_PREFIX_MAP = {'md': "urn:oasis:names:tc:SAML:2.0:metadata"}

REMOVE_NAMESPACE_PREFIXES_XSL_FILE_PATH = 'static/remove_namespace_prefixes.xsl'
REMOVE_KEY_WHITESPACE_XSL_FILE_PATH = 'static/remove_key_whitespace.xsl'


def fetch_spf_sp_entityids(only_production: bool=False):
    from urllib.request import urlopen
    from json import loads

    request = urlopen('https://centres.clarin.eu/api/model/SAMLServiceProvider')
    saml_sps_json = loads(request.read().decode())
    saml_sps_dict = {saml_sp['fields']['entity_id'] for saml_sp in saml_sps_json if
                     not only_production or saml_sp['fields']['production_status']}

    return saml_sps_dict


def process_surfconext_saml_metadata_about_sps(data_generator):
    from lxml.etree import Element

    subtrees = [entitydescriptor for SP_metadata in data_generator for entitydescriptor in
                extract_entitydescriptor_elements(SP_metadata)]
    root = Element('{{{md:s}}}EntitiesDescriptor'.format(md=NAMESPACE_PREFIX_MAP['md']),
                   nsmap=NAMESPACE_PREFIX_MAP)

    for entitydescriptors in subtrees:
        root.append(entitydescriptors)

    return root


def process_saml_metadata_about_sps(saml_metadata: bytes):
    from io import BytesIO
    from lxml.etree import parse, XML, XMLParser, XSLT
    from pkg_resources import resource_stream

    saml_metadata_tree = XML(saml_metadata)

    parser = XMLParser(remove_blank_text=True, resolve_entities=False, remove_comments=False)
    with resource_stream(__name__, REMOVE_NAMESPACE_PREFIXES_XSL_FILE_PATH) as xslt_root1_file:
        xslt_root1 = parse(xslt_root1_file, parser=parser)

        transform1 = XSLT(xslt_root1)
        saml_metadata_tree_1 = transform1(saml_metadata_tree)

    with resource_stream(__name__, REMOVE_KEY_WHITESPACE_XSL_FILE_PATH) as xslt_root2_file:
        xslt_root2 = parse(xslt_root2_file, parser=parser)

    transform2 = XSLT(xslt_root2)
    saml_metadata_2 = transform2(saml_metadata_tree_1)

    canonicalized_saml_metadata_2 = BytesIO()
    saml_metadata_2.write_c14n(canonicalized_saml_metadata_2, exclusive=True, with_comments=False)

    parser = XMLParser(remove_blank_text=True, resolve_entities=False, remove_comments=False)
    saml_metadata_tree_3 = XML(canonicalized_saml_metadata_2.getvalue(), parser).getroottree()

    return saml_metadata_tree_3


def download_all_saml_metadata_from_identity_federations(base_dir_path: str):
    from json import loads as json_loads
    from os.path import join
    # from shutil import move
    # from tempfile import mkdtemp
    from traceback import format_exc
    from logging import warning
    from lxml.etree import tostring
    from urllib.request import urlopen, URLError, HTTPError
    from urllib.parse import quote_plus
    from warnings import warn

    samlidentityfederation_request = urlopen('https://centres.clarin.eu/api/model/SAMLIdentityFederation')

    saml_metadata_urls_json = json_loads(samlidentityfederation_request.read().decode())
    saml_metadata_urls = {elem['fields']['shorthand']: elem['fields']['saml_metadata_url'] for elem in
                          saml_metadata_urls_json}

    samlserviceprovider_request = urlopen('https://centres.clarin.eu/api/model/SAMLServiceProvider')
    saml_sp_entityids_json = json_loads(samlserviceprovider_request.read().decode())
    saml_sp_entityids = [elem['fields']['entity_id'] for elem in saml_sp_entityids_json]

    surfconext_saml_metadata_url = saml_metadata_urls['SURFconext']
    sp_metadata_urls_at_surfconext = [surfconext_saml_metadata_url + '?sp-entity-id=' + quote_plus(SAML_SP_entityID)
                                      for SAML_SP_entityID in saml_sp_entityids]

    pre_surfconext_saml_metadata_about_sps = []

    for SP_metadata_URL in sp_metadata_urls_at_surfconext:
        try:
            saml_metadata = urlopen(SP_metadata_URL).read()
            pre_surfconext_saml_metadata_about_sps += [saml_metadata]
        except HTTPError as e:
            uri_description = '\nThis problem occured with the URL "{url:s}". '.format(url=e.url)
            warning(uri_description)
            warn(format_exc() + uri_description, RuntimeWarning)
        except URLError:
            warning('An URLError occurred. ')
            warn(format_exc(), RuntimeWarning)
            # fp.info().get_content_charset()

    surfconext_saml_metadata_about_sps = process_surfconext_saml_metadata_about_sps(
        pre_surfconext_saml_metadata_about_sps)

    with open(join(base_dir_path, 'SURFconext.xml'), mode='wb') as surfconext_saml_metadata_file:
        processed_surfconext_saml_metadata = process_saml_metadata_about_sps(
            tostring(surfconext_saml_metadata_about_sps, pretty_print=True, encoding='UTF-8', xml_declaration=True))
        surfconext_saml_metadata_file.write(
            tostring(processed_surfconext_saml_metadata, pretty_print=True, encoding='UTF-8', xml_declaration=True))

    saml_metadata_urls = {key: value for (key, value) in saml_metadata_urls.items() if key != 'SURFconext'}

    # Process rest of identity federations.
    for identity_federation_name, saml_metadata_url in saml_metadata_urls.items():
        try:
            saml_metadata = urlopen(saml_metadata_url).read()
        except (URLError, HTTPError):
            uri_description = '\nThis problem occured with the URL "{SAML_metadata_URL:s}". '. \
                format(SAML_metadata_URL=saml_metadata_url)
            warning(format_exc() + uri_description, RuntimeWarning)
        else:
            processed_saml_metadata = process_saml_metadata_about_sps(saml_metadata)
            with open(join(base_dir_path, identity_federation_name + '.xml'),
                      mode='wb') as saml_metadata_file:
                saml_metadata_file.write(
                    tostring(processed_saml_metadata, pretty_print=True, encoding='UTF-8', xml_declaration=True))


def extract_entitydescriptor_elements(xml: bytes):
    from io import BytesIO
    from lxml.etree import parse, XMLParser

    parser = XMLParser(remove_blank_text=True, resolve_entities=False, remove_comments=True)
    tree = parse(BytesIO(xml), parser=parser).getroot()

    entitydescriptors = tree.iterfind('md:EntityDescriptor[md:SPSSODescriptor]',
                                      namespaces=NAMESPACE_PREFIX_MAP)

    for element in entitydescriptors:
        yield element


def get_file_name_and_parent_dir_name(path: str):
    from os.path import join, split

    parent_dir_path, file_name = split(path)
    parent_dir_name = split(parent_dir_path)[1]

    return join(parent_dir_name, file_name)


def encode_entityid(entityid: str):
    from urllib.parse import quote_plus

    return quote_plus(entityid) + '.xml'


def split_identity_federation_saml_metadata_batches_and_diff_entities(base_dir_path: str,
                                                                      spf_sp_entityids: set):
    from glob import iglob
    from lxml.etree import tostring
    from os.path import basename, join, isfile, splitext
    from os import mkdir
    from difflib import unified_diff
    from json import dump

    control_saml_metadata_file_path = join(base_dir_path, CLARIN_IDP_XML_FILE_NAME)

    if not isfile(join(control_saml_metadata_file_path)):
        raise RuntimeError(
            'Control SAML metadata file at "{0}" does not exist. '.format(control_saml_metadata_file_path))
    # Sort SAML metadata filenames to extract control SP metadata in 'CLARIN IdP.xml' first.
    saml_metadata_filenames = [control_saml_metadata_file_path] + \
                              [file_path for file_path in iglob(join(base_dir_path, '*.xml')) if
                               basename(file_path) != CLARIN_IDP_XML_FILE_NAME]

    summary_of_sps_across_identity_federations = dict()

    for saml_metadata_file_path in saml_metadata_filenames:
        if isfile(saml_metadata_file_path):
            identity_federation_name, _ = splitext(basename(saml_metadata_file_path))
            identity_federation_dir_path = join(base_dir_path, identity_federation_name)

            if identity_federation_name != CLARIN_IDP_FED_NAME:
                summary_of_sps_across_identity_federations[identity_federation_name] = []

            mkdir(identity_federation_dir_path)

            with open(saml_metadata_file_path, mode='rb') as SAML_metadata_file:
                for entitydescriptor_element in extract_entitydescriptor_elements(SAML_metadata_file.read()):
                    processed_entitydescriptor_element = \
                        process_saml_metadata_about_sps(
                            tostring(entitydescriptor_element, pretty_print=True, encoding='UTF-8',
                                     xml_declaration=True))

                    entityid = entitydescriptor_element.attrib['entityID']
                    entitydescriptor_file_name = encode_entityid(entityid)
                    entitydescriptor_file_path = join(identity_federation_dir_path, entitydescriptor_file_name)

                    if entityid in spf_sp_entityids:
                        production_sp_xml = tostring(processed_entitydescriptor_element, pretty_print=True,
                                                     encoding='UTF-8', xml_declaration=True)
                        with open(entitydescriptor_file_path, mode='wb') as entitydescriptor_file:
                            entitydescriptor_file.write(production_sp_xml)

                        if identity_federation_name != CLARIN_IDP_FED_NAME:
                            control_entitydescriptor_file_path = join(base_dir_path, CLARIN_IDP_FED_NAME,
                                                                      entitydescriptor_file_name)
                            with open(control_entitydescriptor_file_path,
                                      mode='rt', encoding='UTF-8') as control_entitydescriptor_file:
                                control_entitydescriptor_file_lines = control_entitydescriptor_file.readlines()

                            summary_of_sps_across_identity_federations[identity_federation_name].append(entityid)

                            # Create unified diff between control and current SAML metadata about an SP.
                            entitydescriptor_diff_file_path = entitydescriptor_file_path + '.diff'

                            differences = [difference_line for difference_line in
                                           unified_diff(
                                               a=production_sp_xml.decode(encoding='UTF-8').splitlines(True),
                                               b=control_entitydescriptor_file_lines,
                                               fromfile=get_file_name_and_parent_dir_name(
                                                   entitydescriptor_file_path),
                                               tofile=get_file_name_and_parent_dir_name(
                                                   control_entitydescriptor_file_path))]

                            with open(entitydescriptor_diff_file_path, mode='wt',
                                      encoding='UTF-8') as entitydescriptor_diff_file:
                                entitydescriptor_diff_file.writelines(differences)

    summary_dir_path = join(base_dir_path, 'summary.json')
    with open(summary_dir_path, mode='wt', encoding='UTF-8') as summary_file:
        dump(summary_of_sps_across_identity_federations, summary_file, indent=4, sort_keys=True)


if __name__ == '__main__':
    from argparse import ArgumentParser
    from logging import basicConfig, INFO
    from os import umask
    from os.path import join
    from pathlib import Path

    basicConfig(level=INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    parser = ArgumentParser(description='Collects, filters, splits/aggregates, SAML metadata about CLARIN SPF SPs '
                                        'across identity federations to assess its current state. ')
    parser.add_argument('-base_dir_path', type=Path, help='Base directory path')
    parser.add_argument('-commands', metavar='commands', type=str, nargs='+', help='Command(s) to execute')

    args = parser.parse_args()

    base_dir_path = str(args.base_dir_path)

    commands = args.commands

    valid_commands = (
        download_all_saml_metadata_from_identity_federations.__name__,
        split_identity_federation_saml_metadata_batches_and_diff_entities.__name__,)

    if any(command not in valid_commands for command in commands):
        raise RuntimeError('One invalid and/or zero valid commands specified: {commands}'.format(commands=commands))

    umask(0o022)
    with TempDir(base_dir_path=base_dir_path,
                 suffix='SPF_SAML_metadata_processor',
                 directory_permissions=DIRECTORY_PERMISSIONS,
                 do_restore_mtimes=True) as temp_dir:
        if download_all_saml_metadata_from_identity_federations.__name__ in commands:
            download_all_saml_metadata_from_identity_federations(base_dir_path=temp_dir.temp_base_dir_path)

            if split_identity_federation_saml_metadata_batches_and_diff_entities.__name__ in commands:
                spf_sp_entityids = fetch_spf_sp_entityids()

                split_identity_federation_saml_metadata_batches_and_diff_entities(
                    base_dir_path=temp_dir.temp_base_dir_path,
                    spf_sp_entityids=spf_sp_entityids)
