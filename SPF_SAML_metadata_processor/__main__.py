#!/usr/bin/env python3
import logging
from argparse import ArgumentParser
from difflib import unified_diff
from glob import iglob
from io import BytesIO
from json import dump
from json import loads
from os import mkdir
from os import umask
from os.path import basename
from os.path import isfile
from os.path import join
from os.path import split
from os.path import splitext
from pathlib import Path
from stat import S_IRGRP
from stat import S_IROTH
from stat import S_IRUSR
from stat import S_ISGID
from stat import S_IWUSR
from stat import S_IXGRP
from stat import S_IXOTH
from stat import S_IXUSR
from traceback import format_exc
from urllib.parse import quote_plus
from urllib.error import HTTPError
from urllib.error import URLError
from urllib.request import urlopen

from lxml.etree import parse
from lxml.etree import tostring
from lxml.etree import XML
from lxml.etree import XMLParser
from lxml.etree import XSLT
from importlib_resources import files

from SPF_SAML_metadata_processor.tempdir import TempDir

CLARIN_IDP_FED_NAME = 'CLARIN IdP'
CLARIN_IDP_XML_FILE_NAME = CLARIN_IDP_FED_NAME + '.xml'

DIRECTORY_PERMISSIONS = S_ISGID | S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | \
                        S_IXGRP | S_IROTH | S_IXOTH

NAMESPACE_PREFIX_MAP = {
    "md": "urn:oasis:names:tc:SAML:2.0:metadata",
    "mdrpi": "urn:oasis:names:tc:SAML:metadata:rpi",
    "mdattr": "urn:oasis:names:tc:SAML:metadata:attribute",
    "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
}

REMOVE_NAMESPACE_PREFIXES_XSL_FILE_PATH = \
    'static/remove_namespace_prefixes.xsl'
REMOVE_KEY_WHITESPACE_XSL_FILE_PATH = 'static/remove_key_whitespace.xsl'


def fetch_spf_sp_entityids(only_prod: bool=False):
    rqst = urlopen('https://centres.clarin.eu/api/model/SAMLServiceProvider')
    saml_sps_json = loads(rqst.read().decode())
    saml_sps_dict = {
        saml_sp['fields']['entity_id']
        for saml_sp in saml_sps_json
        if not only_prod or saml_sp['fields']['production_status']
    }

    return saml_sps_dict


def process_saml_md_about_sps(saml_md: bytes):
    saml_md_tree = XML(saml_md)
    localparser = XMLParser(
        remove_blank_text=True, resolve_entities=False, remove_comments=False)
    ref = files('SPF_SAML_metadata_processor').joinpath(REMOVE_NAMESPACE_PREFIXES_XSL_FILE_PATH)
    with ref.open('rb') as xslt_root1_file:
        xslt_root1 = parse(xslt_root1_file, parser=localparser)

        transform1 = XSLT(xslt_root1)
        saml_md_tree_1 = transform1(saml_md_tree)

    ref = files('SPF_SAML_metadata_processor').joinpath(REMOVE_KEY_WHITESPACE_XSL_FILE_PATH)
    with ref.open('rb') as xslt_root2_file:
        xslt_root2 = parse(xslt_root2_file, parser=localparser)

    transform2 = XSLT(xslt_root2)
    saml_md_2 = transform2(saml_md_tree_1)

    canonicalized_saml_md_2 = BytesIO()
    saml_md_2.write_c14n(
        canonicalized_saml_md_2, exclusive=True, with_comments=False)

    saml_md_tree_3 = XML(canonicalized_saml_md_2.getvalue(),
                         localparser).getroottree()

    return saml_md_tree_3


def download_all_saml_md_from_id_feds(base_dir_path: str):
    saml_id_fed_rqst = urlopen(
        'https://centres.clarin.eu/api/model/SAMLIdentityFederation')

    saml_md_urls_json = loads(saml_id_fed_rqst.read().decode())
    saml_md_urls = {elem['fields']['shorthand']: elem['fields']['saml_metadata_url']
                    for elem in saml_md_urls_json}

    saml_md_urls = {key: value
                    for (key, value) in saml_md_urls.items()}

    # Process rest of identity federations.
    for id_fed_name, saml_md_url in saml_md_urls.items():
        try:
            saml_md = urlopen(saml_md_url).read()
        except (URLError, HTTPError):
            uri_descr = '\nThis problem occured with the URL "{SAML_metadata_URL:s}". '. \
                format(SAML_metadata_URL=saml_md_url)
            logging.warning("{}".format(format_exc() + uri_descr, RuntimeWarning))
        else:
            processed_saml_md = process_saml_md_about_sps(saml_md)
            with open(
                    join(base_dir_path, id_fed_name + '.xml'),
                    mode='wb') as saml_md_file:
                saml_md_file.write(
                    tostring(
                        processed_saml_md,
                        pretty_print=True,
                        encoding='UTF-8',
                        xml_declaration=True))

def generate_federation_extra_sps_summary(base_dir_path: str, spf_sp_entityids: set):

    saml_md_filenames = [file_path for file_path in
                         iglob(join(base_dir_path, '*.xml')) if
                         basename(file_path) != CLARIN_IDP_XML_FILE_NAME]

    federation_sps = dict()

    for federation_md_file_path in saml_md_filenames:
        if isfile(federation_md_file_path):
            fed_name, _ = splitext(basename(federation_md_file_path))

            extra_sps_at_federation = get_extra_clarin_sps_in_federation(fed_name, federation_md_file_path, spf_sp_entityids)
            if extra_sps_at_federation:
                federation_sps[fed_name] = []
                for sp in extra_sps_at_federation:
                    federation_sps[fed_name].append(sp)
    logging.info("Generating 'extra_sps_at_federations.json' page...")
    summary_path = join(base_dir_path, "extra_sps_at_federations.json")
    with open(
        summary_path,
        mode='w') as summary_file:
        dump(federation_sps,
            summary_file,
            indent=4,
            sort_keys=True)

def get_extra_clarin_sps_in_federation(id_fed_name: str, federation_md_file_path: str, spf_sp_entityids: set):
    logging.info("Finding non-existent CLARIN SPs in {}...".format(id_fed_name))
    clarin_entityids_at_federation = get_federation_clarin_sps(id_fed_name, federation_md_file_path)
    extra_sps_at_federation = clarin_entityids_at_federation.difference(spf_sp_entityids)
    logging.info("The following CLARIN SPs exist at {} but are not part of the SPF: {}".format(id_fed_name, extra_sps_at_federation))
    return sorted(extra_sps_at_federation)

def get_federation_clarin_sps(id_fed_name: str,federation_md_file_path: str):
    logging.info("Selecting SP entity IDs from {}...".format(id_fed_name))
    with open(federation_md_file_path, "rb") as clarin_sps_at_federation_file:
        clarin_sps_at_federation_md = XML(clarin_sps_at_federation_file.read())
        entities = set()
        xpath = "//md:EntityDescriptor[md:Extensions/mdattr:EntityAttributes/saml:Attribute[\
                        @Name='http://macedir.org/entity-category']/saml:AttributeValue[text() =\
                        'http://clarin.eu/category/clarin-member']]"
        # SURFconext's feed is already only showing CLARIN SPs
        if id_fed_name == "SURFconext":
            xpath = "//md:EntityDescriptor"
        for e in clarin_sps_at_federation_md.xpath(xpath, namespaces=NAMESPACE_PREFIX_MAP):
            entities.add(e.get('entityID'))
    return entities



def extract_entitydescriptor_els(xml: bytes):
    localparser = XMLParser(
        remove_blank_text=True, resolve_entities=False, remove_comments=True)
    tree = parse(BytesIO(xml), parser=localparser).getroot()

    entitydescriptors = tree.iterfind(
        'md:EntityDescriptor[md:SPSSODescriptor]',
        namespaces=NAMESPACE_PREFIX_MAP)

    for element in entitydescriptors:
        yield element


def get_file_name_and_par_dir_name(path: str):
    parent_dir_path, file_name = split(path)
    parent_dir_name = split(parent_dir_path)[1]

    return join(parent_dir_name, file_name)


def encode_entityid(entityid: str):
    return quote_plus(entityid) + '.xml'


def split_id_fed_saml_md_batches_and_diff_entities(base_dir_path: str,
                                                   spf_sp_entityids: set):
    control_saml_md_file_path = join(base_dir_path, CLARIN_IDP_XML_FILE_NAME)

    if not isfile(join(control_saml_md_file_path)):
        raise RuntimeError(
            'Control SAML metadata file at "{0}" does not exist. '.format(
                control_saml_md_file_path))
    # Sort SAML metadata filenames to extract control SP metadata in 'CLARIN
    #  IdP.xml' first.
    saml_md_filenames = [control_saml_md_file_path] + \
                        [file_path for file_path in
                         iglob(join(base_dir_path, '*.xml')) if
                         basename(file_path) != CLARIN_IDP_XML_FILE_NAME]

    summary_of_sps_across_id_feds = dict()

    for saml_md_file_path in saml_md_filenames:
        if isfile(saml_md_file_path):
            id_fed_name, _ = splitext(basename(saml_md_file_path))
            id_fed_dir_path = join(base_dir_path, id_fed_name)

            if id_fed_name != CLARIN_IDP_FED_NAME:
                summary_of_sps_across_id_feds[id_fed_name] = []

            mkdir(id_fed_dir_path)

            with open(saml_md_file_path, mode='rb') as saml_md_file:
                for entitydescriptor_el in \
                        extract_entitydescriptor_els(
                            saml_md_file.read()):
                    processed_entitydescriptor_el = \
                        process_saml_md_about_sps(
                            tostring(entitydescriptor_el,
                                     pretty_print=True, encoding='UTF-8',
                                     xml_declaration=True))

                    entityid = entitydescriptor_el.attrib['entityID']
                    entitydescriptor_file_name = encode_entityid(entityid)
                    entitydescriptor_file_path = join(
                        id_fed_dir_path, entitydescriptor_file_name)

                    if entityid in spf_sp_entityids:
                        prod_sp_xml = tostring(
                            processed_entitydescriptor_el,
                            pretty_print=True,
                            encoding='UTF-8',
                            xml_declaration=True)
                        with open(
                                entitydescriptor_file_path,
                                mode='wb') as entitydescriptor_file:
                            entitydescriptor_file.write(prod_sp_xml)

                        if id_fed_name != CLARIN_IDP_FED_NAME:
                            control_entitydescriptor_file_path = join(
                                base_dir_path, CLARIN_IDP_FED_NAME,
                                entitydescriptor_file_name)
                            with open(control_entitydescriptor_file_path,
                                      mode='rt',
                                      encoding='UTF-8') as \
                                    control_entitydescriptor_file:
                                control_entitydescriptor_file_lines = \
                                    control_entitydescriptor_file.readlines()

                            summary_of_sps_across_id_feds[id_fed_name].append(
                                entityid)

                            # Create unified diff between control and
                            # current SAML metadata about an SP.
                            entitydescriptor_diff_file_path = \
                                entitydescriptor_file_path + '.diff'

                            differences = [
                                difference_line
                                for difference_line in unified_diff(
                                    a=prod_sp_xml.decode(
                                        encoding='UTF-8').splitlines(True),
                                    b=control_entitydescriptor_file_lines,
                                    fromfile=get_file_name_and_par_dir_name(
                                        entitydescriptor_file_path),
                                    tofile=get_file_name_and_par_dir_name(
                                        control_entitydescriptor_file_path))
                            ]

                            with open(entitydescriptor_diff_file_path,
                                      mode='wt',
                                      encoding='utf-8-sig') as \
                                    entitydescriptor_diff_file:
                                entitydescriptor_diff_file.writelines(
                                    differences)

    summary_dir_path = join(base_dir_path, 'summary.json')
    with open(summary_dir_path, mode='wt', encoding='UTF-8') as summary_file:
        dump(
            summary_of_sps_across_id_feds,
            summary_file,
            indent=4,
            sort_keys=True)

if __name__ == '__main__':
    parser = ArgumentParser(
        description='Collects, filters, splits/aggregates, SAML metadata '
        'about CLARIN SPF SPs across identity federations to '
        'assess its current state. ')
    parser.add_argument(
        '-base_dir_path', type=Path, help='Base directory path')
    parser.add_argument(
        '-commands',
        metavar='commands',
        type=str,
        nargs='+',
        help='Command(s) to execute')
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        help="Set the logging level",
        default="INFO")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.log_level), format='%(asctime)s [%(levelname)s]: %(message)s')

    BASE_DIR_PATH = str(args.base_dir_path)
    COMMANDS = args.commands
    VALID_COMMANDS = (
        download_all_saml_md_from_id_feds.__name__,
        split_id_fed_saml_md_batches_and_diff_entities.__name__, )
    if any(command not in VALID_COMMANDS for command in COMMANDS):
        raise RuntimeError(
            'One invalid and/or zero valid commands specified: {commands}'.format(commands=COMMANDS))
    umask(0o022)
    with TempDir(
            base_dir_path=BASE_DIR_PATH,
            suffix='SPF_SAML_metadata_processor',
            directory_permissions=DIRECTORY_PERMISSIONS,
            do_restore_mtimes=True) as temp_dir:
        if download_all_saml_md_from_id_feds.__name__ in \
                COMMANDS:
            download_all_saml_md_from_id_feds(
                base_dir_path=temp_dir.temp_base_dir_path)

            if split_id_fed_saml_md_batches_and_diff_entities.__name__ in \
                    COMMANDS:
                SPF_SP_ENTITYIDS = fetch_spf_sp_entityids()

                split_id_fed_saml_md_batches_and_diff_entities(
                    base_dir_path=temp_dir.temp_base_dir_path,
                    spf_sp_entityids=SPF_SP_ENTITYIDS)

                generate_federation_extra_sps_summary(
                    base_dir_path=temp_dir.temp_base_dir_path,
                    spf_sp_entityids=SPF_SP_ENTITYIDS)
