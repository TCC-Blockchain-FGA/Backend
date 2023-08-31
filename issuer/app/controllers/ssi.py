import time
from indy import anoncreds, crypto, did, ledger, pool, wallet
import json
import logging
import os
from typing import Optional
from indy.error import ErrorCode, IndyError
from src.utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION
import subprocess
import uuid
import app.controllers.database as database
import requests
from flask import Response
import asyncio
import json
import pprint
import sys
from typing import Optional

from src.utils import run_coroutine, get_pool_genesis_txn_path, PROTOCOL_VERSION

from indy import pool, ledger, wallet, did, anoncreds, crypto
from indy.error import IndyError, ErrorCode

from app.controllers.agent import Steward, Issuer, Holder, Validator

seq_no = 1
pool_name = 'pool1'
pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

steward = Steward()
issuer = Issuer()
validator = Validator()
pool_handle = ''
holder_verkey = ''

def print_log(value_color="", value_noncolor=""):
    """set the colors for text."""
    HEADER = '\033[92m'
    ENDC = '\033[0m'
    print(HEADER + value_color + ENDC + str(value_noncolor))

async def pool_genesys(protocol_version, pool_name, pool_config):
    try:
        bashCommand = "bash refresh.sh"
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
    except:
        pass
    await pool.set_protocol_version(protocol_version)
    try:
        print_log('\n1. Creates a new local pool ledger configuration that is used '
                  'later when connecting to ledger.\n')
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as e:
        if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            print('pool already exists!')
        else:
            print('Error occurred: %s' % e)
    try:
        print_log('\n2. Open pool ledger and get handle from libindy\n')
        pool_handle = await pool.open_pool_ledger(pool_name, None)
    except IndyError as e:
        print('Error occurred: %s' % e)
        pool_handle = -1
    return pool_handle

async def start_issuer():
    pool_handle = await pool_genesys(PROTOCOL_VERSION, pool_name=pool_name, pool_config=pool_config)

    await steward.create(pool_handle)
    await issuer.create(pool_handle)
    await validator.create(pool_handle)

    database.updateVerkey(issuer.verkey)
    
    await steward.simple_onboarding(issuer.did, issuer.verkey, issuer.role)
    await steward.simple_onboarding(validator.did, validator.verkey, validator.role)

    schema_id = await steward.new_schema('RegistroPaciente',
                    ['name', 'phone', 'gender', \
                    'dateOfBirth', 'address', 'maritalStatus', \
                    'multipleBirth', 'contactRelationship', 'contactName', \
                    'contactPhone', 'contactAddress', 'contactGender', \
                    'languages', 'preferredLanguage', 'generalPractitioner',])

    await issuer.new_cred_def(schema_id)

async def issue_credential(login):
    connection_request = {
        'did': issuer.did,
        'nonce': hash(issuer.did)
    }
    c_message = await issuer.send_message_ab(json.dumps(connection_request), None)

    URL = "https://146.190.157.57:5001/testRequestsReceiver"
    data = {'data': c_message, 'step': 1, 'login': login}
    c_res = requests.post(url = URL, data = data, verify=False)
    print(c_res._content)
    jres = await issuer.recv_message_ba(c_res._content)
    jres = jres.decode()
    print('jres',jres)

    res = json.loads(jres)
    holder_did = res['did']
    holder_verkey = res['verkey']
    cred_offer_json = await issuer.new_cred_offer(issuer.cred_defs['RegistroPaciente'])

    c_cred_offer_json = await issuer.send_message_ab(cred_offer_json, holder_verkey)
    c_cred_def_id = await issuer.send_message_ab(issuer.cred_defs['RegistroPaciente'], holder_verkey)
    URL = "https://146.190.157.57:5001/testRequestsReceiver"
    data = {'c_cred_offer_json': c_cred_offer_json.decode('latin-1'), 'c_cred_def_id': c_cred_def_id.decode('latin-1'), 'step': 2, 'login': login}

    c_res = requests.post(url = URL, data = data, verify=False)
    jres = await issuer.recv_message_ba(c_res._content)
    res = json.loads(jres)

    cred_req_json = res['cred_req_json']
    cred_values_json = res['cred_values_json']

    cred_json = await issuer.request_to_cred_issue(cred_offer_json, cred_req_json, cred_values_json)

    c_cred_json = await issuer.send_message_ab(cred_json, holder_verkey)
    c_cred_def_id = await issuer.send_message_ab(issuer.cred_defs['RegistroPaciente'], holder_verkey)
    URL = "https://146.190.157.57:5001/testRequestsReceiver"
    data = {'c_cred_json': c_cred_json.decode('latin-1'), 'c_cred_def_id': c_cred_def_id.decode('latin-1'), 'step': 3, 'login': login}
    c_res = requests.post(url = URL, data = data, verify=False)

async def validate_credential():
    proof_req = validator.build_proof_request('RegistroPaciente', '', '')

    connection_request = {
        'did': validator.did,
        'nonce': hash(validator.did)
    }
    c_message = await validator.send_message_ab(json.dumps(connection_request), None)

    URL = "https://146.190.157.57:5001/testRequestsReceiver2"
    data = {'data': c_message, 'step': 1}
    c_res = requests.post(url = URL, data = data, verify=False)
    jres = await validator.recv_message_ba(c_res._content)

    res = json.loads(jres)
    holder_did = res['did']
    holder_verkey = res['verkey']
    c_proof_req = await validator.send_message_ab(proof_req, holder_verkey)
    c_schema_id = await validator.send_message_ab(issuer.schemas['RegistroPaciente'], holder_verkey)
    c_cred_def_id = await validator.send_message_ab(issuer.cred_defs['RegistroPaciente'], holder_verkey)

    URL = "https://146.190.157.57:5001/testRequestsReceiver2"
    data = {'c_proof_req': c_proof_req.decode('latin-1'), 'c_schema_id': c_schema_id.decode('latin-1'), 'c_cred_def_id':c_cred_def_id.decode('latin-1'), 'step': 2}
    c_res = requests.post(url = URL, data = data, verify=False)
    jres = await validator.recv_message_ba(c_res._content)
    res = json.loads(jres)
    proof_json = res['proof_json']
    schemas_json = res['schemas_json']
    cred_defs_json = res['cred_defs_json']

    assert await validator.validate_proof(proof_req, proof_json, schemas_json, cred_defs_json, '{}')

async def delete_and_close(pool_handle):

    await issuer.delete()
    await validator.delete()

    try:
        print_log('\n20. Close and Deleting pool ledger config\n')
        await pool.close_pool_ledger(pool_handle)
        await pool.delete_pool_ledger_config(pool_name)
    except IndyError as e:
            print('Error occurred: %s' % e)

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)
pool_handle = ''
org_wallet = ''
org_did = ''
org_transcript_cred_def_id = ''

def init():
    run_coroutine(run)

async def run():
    await start_issuer()

def create_wallet():
    wallet_config = json.dumps({"id": f'{uuid.uuid4()}'})
    wallet_credentials = json.dumps({"key": f'wallet_key_{uuid.uuid4()}'})
    return [wallet_config, wallet_credentials]

async def generate_credential(user):
    user_wallet_config = user[18]
    user_wallet_credentials = user[19]
    user_name = "Alice"
    user_last_name = "Garcia"
    user_degree = "Bachelor of Science, Marketing"
    user_status = "graduated"
    user_ssn = "123-45-6789"
    user_year = "2015"
    user_average = "5"
    global pool_handle, org_did, org_wallet, org_transcript_cred_def_id

    user_wallet, org_user_key, user_org_did, user_org_key, org_user_connection_response \
         = await onboarding(pool_handle, "org", org_wallet, org_did, user_name, None, user_wallet_config,
                            user_wallet_credentials)

    transcript_cred_offer_json = \
         await anoncreds.issuer_create_credential_offer(org_wallet, org_transcript_cred_def_id)
    user_org_verkey = await did.key_for_did(pool_handle, org_wallet, org_user_connection_response['did'])
    authcrypted_transcript_cred_offer = await crypto.auth_crypt(org_wallet, org_user_key, user_org_verkey,
                                                                 transcript_cred_offer_json.encode('utf-8'))
    org_user_verkey, authdecrypted_transcript_cred_offer_json, authdecrypted_transcript_cred_offer = \
         await auth_decrypt(user_wallet, user_org_key, authcrypted_transcript_cred_offer)
    user_master_secret_id = await anoncreds.prover_create_master_secret(user_wallet, None)
    (org_transcript_cred_def_id, org_transcript_cred_def) = \
         await get_cred_def(pool_handle, user_org_did, authdecrypted_transcript_cred_offer['cred_def_id'])
    (transcript_cred_request_json, transcript_cred_request_metadata_json) = \
         await anoncreds.prover_create_credential_req(user_wallet, user_org_did,
                                                      authdecrypted_transcript_cred_offer_json,
                                                      org_transcript_cred_def, user_master_secret_id)
    authcrypted_transcript_cred_request = await crypto.auth_crypt(user_wallet, user_org_key, org_user_verkey,
                                                                   transcript_cred_request_json.encode('utf-8'))
    user_org_verkey, authdecrypted_transcript_cred_request_json, _ = \
         await auth_decrypt(org_wallet, org_user_key, authcrypted_transcript_cred_request)
    transcript_cred_values = json.dumps({
         "first_name": {"raw": user_name, "encoded": "1139481716457488690172217916278103335"},
         "last_name": {"raw": user_last_name, "encoded": "5321642780241790123587902456789123452"},
         "degree": {"raw": user_degree, "encoded": "12434523576212321"},
         "status": {"raw": user_status, "encoded": "2213454313412354"},
         "ssn": {"raw": user_ssn, "encoded": "3124141231422543541"},
         "year": {"raw": user_year, "encoded": "2015"},
         "average": {"raw": user_average, "encoded": "5"}
    })

    transcript_cred_json, _, _ = \
         await anoncreds.issuer_create_credential(org_wallet, transcript_cred_offer_json,
                                                  authdecrypted_transcript_cred_request_json,
                                                  transcript_cred_values, None, None)
    authcrypted_transcript_cred_json = await crypto.auth_crypt(org_wallet, org_user_key, user_org_verkey,
                                                                transcript_cred_json.encode('utf-8'))
    _, authdecrypted_transcript_cred_json, _ = \
         await auth_decrypt(user_wallet, user_org_key, authcrypted_transcript_cred_json)
    await anoncreds.prover_store_credential(user_wallet, None, transcript_cred_request_metadata_json,
                                             authdecrypted_transcript_cred_json, org_transcript_cred_def, None)

    return True

async def get_proof(user):
    user_wallet_config =  user[18]
    user_wallet_credentials = user[19]
    user_name = "Alice"

    user_wallet, org_user_key, user_org_did, user_org_key, org_user_connection_response = \
         await onboarding(pool_handle, "org", org_wallet, org_did, user_name, user_wallet, user_wallet_config,
                          user_wallet_credentials)

    job_application_proof_request_json = json.dumps({
         'nonce': '1432422343242122312411212',
         'name': 'Job-Application',
         'version': '0.1',
         'requested_attributes': {
             'attr1_referent': {
                 'name': 'first_name'
             },
             'attr2_referent': {
                 'name': 'last_name'
             },
             'attr3_referent': {
                 'name': 'degree',
                 'restrictions': [{'cred_def_id': org_transcript_cred_def_id}]
             },
             'attr4_referent': {
                 'name': 'status',
                 'restrictions': [{'cred_def_id': org_transcript_cred_def_id}]
             },
             'attr5_referent': {
                 'name': 'ssn',
                 'restrictions': [{'cred_def_id': org_transcript_cred_def_id}]
             },
             'attr6_referent': {
                 'name': 'phone_number'
             }
         },
         'requested_predicates': {
             'predicate1_referent': {
                 'name': 'average',
                 'p_type': '>=',
                 'p_value': 4,
                 'restrictions': [{'cred_def_id': org_transcript_cred_def_id}]
             }
         }
    })

    user_org_verkey = await did.key_for_did(pool_handle, org_wallet, org_user_connection_response['did'])

    authcrypted_job_application_proof_request_json = \
         await crypto.auth_crypt(org_wallet, org_user_key, user_org_verkey,
                                 job_application_proof_request_json.encode('utf-8'))
    org_user_verkey, authdecrypted_job_application_proof_request_json, _ = \
         await auth_decrypt(user_wallet, user_org_key, authcrypted_job_application_proof_request_json)
    search_for_job_application_proof_request = \
         await anoncreds.prover_search_credentials_for_proof_req(user_wallet,
                                                                 authdecrypted_job_application_proof_request_json, None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
         await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    creds_for_job_application_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                        cred_for_attr2['referent']: cred_for_attr2,
                                        cred_for_attr3['referent']: cred_for_attr3,
                                        cred_for_attr4['referent']: cred_for_attr4,
                                        cred_for_attr5['referent']: cred_for_attr5,
                                        cred_for_predicate1['referent']: cred_for_predicate1}

    schemas_json, cred_defs_json, revoc_states_json = \
         await prover_get_entities_from_ledger(pool_handle, user_org_did, creds_for_job_application_proof, 'user')

    job_application_requested_creds_json = json.dumps({
         'self_attested_attributes': {
             'attr1_referent': 'Alice',
             'attr2_referent': 'Garcia',
             'attr6_referent': '123-45-6789'
         },
         'requested_attributes': {
             'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
             'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
             'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
         },
         'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    job_application_proof_json = \
         await anoncreds.prover_create_proof(user_wallet, authdecrypted_job_application_proof_request_json,
                                             job_application_requested_creds_json, user_master_secret_id,
                                             schemas_json, cred_defs_json, revoc_states_json)
    authcrypted_job_application_proof_json = await crypto.auth_crypt(user_wallet, user_org_key, org_user_verkey,
                                                                      job_application_proof_json.encode('utf-8'))
    _, decrypted_job_application_proof_json, decrypted_job_application_proof = \
         await auth_decrypt(org_wallet, org_user_key, authcrypted_job_application_proof_json)

    schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json = \
         await verifier_get_entities_from_ledger(pool_handle, org_did,
                                                 decrypted_job_application_proof['identifiers'], 'org')
    assert 'Bachelor of Science, Marketing' == \
            decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
            decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
            decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'Alice' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(job_application_proof_request_json,
                                                  decrypted_job_application_proof_json,
                                                  schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json)

async def onboarding(pool_handle, _from, from_wallet, from_did, to, to_wallet: Optional[str], to_wallet_config: str,
                     to_wallet_credentials: str):
    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from, _from, to))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(from_wallet, "{}")

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, _from, to))
    await send_nym(pool_handle, from_wallet, from_did, from_to_did, from_to_key, None)

    logger.info("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce".format(_from, to, _from, to))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if not to_wallet:
        logger.info("\"{}\" -> Create wallet".format(to))
        try:
            await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)

    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to, to, _from))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Get key for did from \"{}\" connection request".format(to, _from))
    from_to_verkey = await did.key_for_did(pool_handle, to_wallet, connection_request['did'])

    logger.info("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
                .format(to, _from, to, _from))
    connection_response = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    anoncrypted_connection_response = await crypto.anon_crypt(from_to_verkey, connection_response.encode('utf-8'))

    logger.info("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to, _from))

    logger.info("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from, to))
    decrypted_connection_response = \
        json.loads((await crypto.anon_decrypt(from_wallet, from_to_key,
                                              anoncrypted_connection_response)).decode("utf-8"))

    logger.info("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from, to))
    assert connection_request['nonce'] == decrypted_connection_response['nonce']

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, to, _from))
    await send_nym(pool_handle, from_wallet, from_did, to_from_did, to_from_key, None)

    return to_wallet, from_to_key, to_from_did, to_from_key, decrypted_connection_response


async def get_verinym(pool_handle, _from, from_wallet, from_did, from_to_key,
                      to, to_wallet, to_from_did, to_from_key, role):
    logger.info("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to, to))
    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to, to, _from))
    did_info_json = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    authcrypted_did_info_json = \
        await crypto.auth_crypt(to_wallet, to_from_key, from_to_key, did_info_json.encode('utf-8'))

    logger.info("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to, to, _from))

    logger.info("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from, to, to))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(from_wallet, from_to_key, authcrypted_did_info_json)

    logger.info("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from, to, ))
    assert sender_verkey == await did.key_for_did(pool_handle, from_wallet, to_from_did)

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role".format(_from, to, role))
    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], role)

    return to_did


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, schema_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, schema_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message
