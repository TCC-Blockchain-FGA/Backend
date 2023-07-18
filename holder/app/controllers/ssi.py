import re
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

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

from app.controllers.agent import Holder

seq_no = 1
pool_name = 'pool1'
pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})
prover = Holder()


def init():
    run_coroutine(run)

def print_log(value_color="", value_noncolor=""):
    """set the colors for text."""
    HEADER = '\033[92m'
    ENDC = '\033[0m'
    print(HEADER + value_color + ENDC + str(value_noncolor))

async def pool_genesys(protocol_version, pool_name, pool_config):
    # Set protocol version 2 to work with Indy Node 1.4
    try:
        bashCommand = "bash refresh.sh"
        process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()
    except:
        pass
    await pool.set_protocol_version(protocol_version)
    try:
        # 1.
        print_log('\n1. Creates a new local pool ledger configuration that is used '
                  'later when connecting to ledger.\n')
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as e:
        if e.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            print('pool already exists!')
        else:
            print('Error occurred: %s' % e)
    try:
        # 2.
        print_log('\n2. Open pool ledger and get handle from libindy\n')
        pool_handle = await pool.open_pool_ledger(pool_name, None)
    except IndyError as e:
        print('Error occurred: %s' % e)
        pool_handle = -1
    return pool_handle

async def start_holder():
    pool_handle = await pool_genesys(PROTOCOL_VERSION, pool_name=pool_name, pool_config=pool_config)
    await prover.create(pool_handle)

async def issue_credential(connection_request, step):
    print("\n\nAQUIIIIIIIIIIIIIIIIIIIIIIIIIIIIII\n\n")
    # print("\n\n\n", connection_request)

    if step == '1':
        print(connection_request)

        res = await prover.connect_did(json.loads(connection_request))
        print(res)
        return res
        #cred_offer_json = await issuer.new_cred_offer(cred_def_id)

        ## Issuer Crypt
        ## Issuer send message to holder with (cred_offer_json, cred_def_id)
        # o cred_def_id ja esta dentro do cred_offer_json
        ## Holder Decrypt

    if step == '2':
        mes :str = connection_request[0]
        message = await prover.recv_message_ba(mes)
        message2 = await prover.recv_message_ba(connection_request[1])
        print('message', message)
        print('message2', message2)
        # message = {'cred_offer_json': connection_request[0], 'cred_def_id': connection_request[1]}
        # print('message', message)
        return 'sucess'
        (cred_req_json, cred_req_metadata_json) = await prover.offer_to_cred_request(message['cred_offer_json'], message['cred_def_id'])

        #### precisa parar e fazer o cadastro do forms

        ## falta fazer o encoded automatico
        cred_values_json = json.dumps({
            'name': {'raw': 'matheus', 'encoded': '12345'}, 'phone': {'raw': '61912341234', 'encoded': '12345'}, 'gender': {'raw': 'm', 'encoded': '12345'}, \
            'dateOfBirth': {'raw': '19990101', 'encoded': '12345'}, 'address':{'raw': 'Brasilia', 'encoded': '12345'}, 'maritalStatus': {'raw': 'abc', 'encoded': '12345'}, \
            'multipleBirth': {'raw': '0', 'encoded': '12345'}, 'contactRelationship': {'raw': 'a', 'encoded': '12345'}, 'contactName': {'raw': 'mamama', 'encoded': '12345'}, \
            'contactPhone': {'raw': '61901011010', 'encoded': '12345'}, 'contactAddress': {'raw': 'Brasilia', 'encoded': '12345'}, 'contactGender': {'raw': 'm', 'encoded': '12345'}, \
            'languages': {'raw': 'pt', 'encoded': '12345'}, 'preferredLanguage': {'raw': 'pt', 'encoded': '12345'}, 'generalPractitioner': {'raw': 'abccba', 'encoded': '12345'},
        })
        return await prover.send_message_ab(json.dumps({'cred_req_json': cred_req_json, 'cred_values_json': cred_values_json}), prover.issuer_verkey)

    ## Holder Crypt
    ## Holder send message to Issuer with (cred_req_json, cred_values_json)
    ## Issuer Decrypt

    #
    # cred_json = await issuer.request_to_cred_issue(cred_offer_json, cred_req_json, cred_values_json)
    if step == '3':
        # message = json.loads(prover.recv_message_ba(connection_request))

        message = {'cred_offer_json': connection_request[0], 'cred_def_id': connection_request[1]}
        print(message)
    ## Issuer Crypt
    ## Issuer send message to Holder with (cred_json, cred_def_id)
    ## Holder Decrypt

        await prover.store_ver_cred(cred_req_metadata_json, message['cred_json'], message['cred_def_id'])
        return 'Success'

async def validate_credential(c_message):

    ## Validator handshake DID with Holder

    #
    #proof_req = validator.build_proof_request('gvt', '', '')

    ## Validator crypt
    ## Validator send message to Holder with (proof_req)
    ## Holder decrypt

    message = json.loads(prover.recv_message_ba(c_message))


    ## falta buscar esses schemas e cred_defs sozinho no ledger (desaclopar)
    proof_json, schemas_json, cred_defs_json = await prover.proof_req_to_get_cred(message['proof_req'], message['schema_id'], message['cred_def_id'])

    return await prover.send_message_ab(json.dumps({'proof_json': proof_json, 'schemas_json': schemas_json, 'cred_defs_json': cred_defs_json}), prover.issuer_verkey)
    ## Holder crypt
    ## Holder send message to Validator with (proof_req)
    ## Validator decrypt

    #
    #assert await validator.validate_proof(proof_req, proof_json, schemas_json, cred_defs_json, '{}')

    ###

async def delete_and_close(prover, pool_handle):

    await prover.delete()

    try:
        # 20.
        print_log('\n20. Close and Deleting pool ledger config\n')
        await pool.close_pool_ledger(pool_handle)
        await pool.delete_pool_ledger_config(pool_name)
    except IndyError as e:
            print('Error occurred: %s' % e)






async def run():
    await start_holder()
    # issue_credential(prover)
    # validate_credential(prover)
    # delete_and_close(prover, pool_handle)


async def generate_credential(user):
    user_wallet_config = user[18]
    user_wallet_credentials = user[19]
    user_name = "Alice" #user[3]
    user_last_name = "Garcia" #user[3]
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
