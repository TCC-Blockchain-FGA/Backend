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
pool_handle = ''
admin_wallet = ''
admin_did = ''

def init():
    run_coroutine(run)

async def run():
    global pool_handle, admin_wallet, admin_did

    bashCommand = "bash refresh.sh"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    pool_name = 'pool1'
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})

    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_handle = await pool.open_pool_ledger(pool_name, None)

    admin_wallet_config = json.dumps({"id": "admin_wallet"})
    admin_wallet_credentials = json.dumps({"key": "admin_wallet_key"})
    try:
        await wallet.create_wallet(admin_wallet_config, admin_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    admin_wallet = await wallet.open_wallet(admin_wallet_config, admin_wallet_credentials)

    admin_did_info = {'seed': '000000000000000000000000Steward1'}
    (admin_did, admin_key) = await did.create_and_store_my_did(admin_wallet, json.dumps(admin_did_info))

async def create_wallet_and_set_trust_anchor(name):
    global pool_handle, admin_wallet, admin_did
    wallet_config = json.dumps({"id": f'{uuid.uuid4()}'})
    wallet_credentials = json.dumps({"key": f'wallet_key_{uuid.uuid4()}'})
    obj_wallet, admin_obj_key, obj_admin_did, obj_admin_key, _ = await onboarding(pool_handle, "Admin", admin_wallet, admin_did, name, None, wallet_config, wallet_credentials)
    obj_did = await get_verinym(pool_handle, "Admin", admin_wallet, admin_did, admin_obj_key, name, obj_wallet, obj_admin_did, obj_admin_key, 'TRUST_ANCHOR')
    # print(wallet_config, wallet_credentials, obj_wallet)
    return True

async def create_wallet(org, org_wallet, org_did, name):
    global pool_handle
    wallet_config = json.dumps({"id": f'{uuid.uuid4()}'})
    wallet_credentials = json.dumps({"key": f'wallet_key_{uuid.uuid4()}'})
    obj_wallet, org_obj_key, obj_org_did, obj_org_key, org_obj_connection_response = await onboarding(pool_handle, org, org_wallet, org_did, name, None, wallet_config, wallet_credentials)
    return True


async def create_schema(schema):
    ##### EXEMPLO DE ESQUEMA
    # ['first_name', 'last_name', 'salary', 'employee_status', 'experience']
    global pool_handle, admin_wallet, admin_did
    (job_certificate_schema_id, job_certificate_schema) = await anoncreds.issuer_create_schema(admin_did, 'Job-Certificate', '0.2', json.dumps(schema))
    await send_schema(pool_handle, admin_wallet, admin_did, job_certificate_schema)
    time.sleep(1)
    return True

async def create_schema_definition(obj_did, obj_wallet, schema_id):
    global pool_handle
    (_, schema) = await get_schema(pool_handle, obj_did, schema_id)
    (obj_cred_def_id, obj_cred_def_json) = \
    await anoncreds.issuer_create_and_store_credential_def(obj_wallet, obj_did, schema, 'TAG1', 'CL', '{"support_revocation": false}')

    await send_cred_def(pool_handle, obj_wallet, obj_did, obj_cred_def_json)
    return True

async def create_certificate(obj_did, obj_wallet, schema_id):
     obj_wallet_config = json.dumps({"id": obj_wallet})
     obj_wallet_credentials = json.dumps({"key": obj_wallet_key})
     obj_wallet, org_obj_key, obj_org_did, obj_org_key, org_obj_connection_response \
         = await onboarding(pool_handle, org_name, org_wallet, org_did, obj_name, None, obj_wallet_config,
                            obj_wallet_credentials)

#      transcript_cred_offer_json = \
#          await anoncreds.issuer_create_credential_offer(org_wallet, org_transcript_cred_def_id)
#
#      obj_org_verkey = await did.key_for_did(pool_handle, buss_wallet, org_obj_connection_response['did'])
#      authcrypted_transcript_cred_offer = await crypto.auth_crypt(org_wallet, org_obj_key, obj_org_verkey,
#      org_obj_verkey, authdecrypted_transcript_cred_offer_json, authdecrypted_transcript_cred_offer = \
#          await auth_decrypt(obj_wallet, obj_org_key, authcrypted_transcript_cred_offer)
#
#      obj_master_secret_id = await anoncreds.prover_create_master_secret(nilo_wallet, None)
#
#      (org_transcript_cred_def_id, org_transcript_cred_def) = \
#          await get_cred_def(pool_handle, obj_org_did, authdecrypted_transcript_cred_offer['cred_def_id'])
#
#      (transcript_cred_request_json, transcript_cred_request_metadata_json) = \
#          await anoncreds.prover_create_credential_req(obj_wallet, obj_org_did,
#                                                       authdecrypted_transcript_cred_offer_json,
#                                                       org_transcript_cred_def, obj_master_secret_id)
#
#      authcrypted_transcript_cred_request = await crypto.auth_crypt(obj_wallet, obj_org_key, org_obj_verkey,
#                                                                    transcript_cred_request_json.encode('utf-8'))
#
#      obj_org_verkey, authdecrypted_transcript_cred_request_json, _ = \
#          await auth_decrypt(org_wallet, org_obj_key, authcrypted_transcript_cred_request)
#      transcript_cred_values = json.dumps({
#          "first_name": {"raw": obj_name, "encoded": "1139481716457488690172217916278103335"},
#          "last_name": {"raw": obj_last_name, "encoded": "5321642780241790123587902456789123452"},
#          "degree": {"raw": obj_degree, "encoded": "12434523576212321"},
#          "status": {"raw": obj_states, "encoded": "2213454313412354"},
#          "ssn": {"raw": obj_ssn, "encoded": "3124141231422543541"},
#          "year": {"raw": obj_year, "encoded": "2015"},
#          "average": {"raw": obj_average, "encoded": "5"}
#      })
#
#      transcript_cred_json, _, _ = \
#          await anoncreds.issuer_create_credential(org_wallet, transcript_cred_offer_json,
#                                                   authdecrypted_transcript_cred_request_json,
#                                                   transcript_cred_values, None, None)
#      authcrypted_transcript_cred_json = await crypto.auth_crypt(org_wallet, org_obj_key, obj_org_verkey,
#                                                                 transcript_cred_json.encode('utf-8'))
#
#      _, authdecrypted_transcript_cred_json, _ = \
#          await auth_decrypt(obj_wallet, obj_org_key, authcrypted_transcript_cred_json)
#
#      await anoncreds.prover_store_credential(obj_wallet, None, transcript_cred_request_metadata_json,
#                                              authdecrypted_transcript_cred_json, org_transcript_cred_def, None)
#
# async def get_proof_request(obj_did, obj_wallet, schema_id):
#      logger.info("== Verificacao das credenciais de trabalho==")
#      logger.info("------------------------------")
#
#      _, bancoy_nilo_key, nilo_bancoy_did, nilo_bancoy_key, \
#      bancoy_nilo_connection_response = await onboarding(pool_handle, "bancoy", bancoy_wallet, bancoy_did, "nilo",
#                                                          nilo_wallet, nilo_wallet_config, nilo_wallet_credentials)

# -----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
     # logger.info("\"bancoy\" -> Create \"Loan-Application-Basic\" Proof Request")
     # apply_loan_proof_request_json = json.dumps({
     #     'nonce': '123432421212',
     #     'name': 'Loan-Application-Basic',
     #     'version': '0.1',
     #     'requested_attributes': {
     #         'attr1_referent': {
     #             'name': 'employee_status',
     #             'restrictions': [{'cred_def_id': empresax_job_certificate_cred_def_id}]
     #         }
     #     },
     #     'requested_predicates': {
     #         'predicate1_referent': {
     #             'name': 'salary',
     #             'p_type': '>=',
     #             'p_value': 2000,
     #             'restrictions': [{'cred_def_id': empresax_job_certificate_cred_def_id}]
     #         },
     #         'predicate2_referent': {
     #             'name': 'experience',
     #             'p_type': '>=',
     #             'p_value': 1,
     #             'restrictions': [{'cred_def_id': empresax_job_certificate_cred_def_id}]
     #         }
     #     }
     # })
     #
     # logger.info("\"bancoy\" -> Get key for nilo did")
     # nilo_bancoy_verkey = await did.key_for_did(pool_handle, bancoy_wallet, bancoy_nilo_connection_response['did'])
     #
     # logger.info("\"bancoy\" -> Authcrypt \"Loan-Application-Basic\" Proof Request for nilo")
     # authcrypted_apply_loan_proof_request_json = \
     #     await crypto.auth_crypt(bancoy_wallet, bancoy_nilo_key, nilo_bancoy_verkey,
     #                             apply_loan_proof_request_json.encode('utf-8'))
     #
     # logger.info("\"bancoy\" -> Send authcrypted \"Loan-Application-Basic\" Proof Request to nilo")
     #
     # logger.info("\"nilo\" -> Authdecrypt \"Loan-Application-Basic\" Proof Request from bancoy")
     # bancoy_nilo_verkey, authdecrypted_apply_loan_proof_request_json, _ = \
     #     await auth_decrypt(nilo_wallet, nilo_bancoy_key, authcrypted_apply_loan_proof_request_json)
     #
     # logger.info("\"nilo\" -> Get credentials for \"Loan-Application-Basic\" Proof Request")
     #
     # search_for_apply_loan_proof_request = \
     #     await anoncreds.prover_search_credentials_for_proof_req(nilo_wallet,
     #                                                             authdecrypted_apply_loan_proof_request_json, None)
     #
     # cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'attr1_referent')
     # cred_for_predicate1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate1_referent')
     # cred_for_predicate2 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate2_referent')
     #
     # await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_proof_request)
     #
     # creds_for_apply_loan_proof = {cred_for_attr1['referent']: cred_for_attr1,
     #                               cred_for_predicate1['referent']: cred_for_predicate1,
     #                               cred_for_predicate2['referent']: cred_for_predicate2}
     #
     # schemas_json, cred_defs_json, revoc_states_json = \
     #     await prover_get_entities_from_ledger(pool_handle, nilo_bancoy_did, creds_for_apply_loan_proof, 'nilo')
     #
     # logger.info("\"nilo\" -> Create \"Loan-Application-Basic\" Proof")
     # apply_loan_requested_creds_json = json.dumps({
     #     'self_attested_attributes': {},
     #     'requested_attributes': {
     #         'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True}
     #     },
     #     'requested_predicates': {
     #         'predicate1_referent': {'cred_id': cred_for_predicate1['referent']},
     #         'predicate2_referent': {'cred_id': cred_for_predicate2['referent']}
     #     }
     # })
     # nilo_apply_loan_proof_json = \
     #     await anoncreds.prover_create_proof(nilo_wallet, authdecrypted_apply_loan_proof_request_json,
     #                                         apply_loan_requested_creds_json, nilo_master_secret_id, schemas_json,
     #                                         cred_defs_json, revoc_states_json)
     #
     # logger.info("\"nilo\" -> Authcrypt \"Loan-Application-Basic\" Proof for bancoy")
     # authcrypted_nilo_apply_loan_proof_json = \
     #     await crypto.auth_crypt(nilo_wallet, nilo_bancoy_key, bancoy_nilo_verkey,
     #                             nilo_apply_loan_proof_json.encode('utf-8'))
     #
     # logger.info("\"nilo\" -> Send authcrypted \"Loan-Application-Basic\" Proof to bancoy")
     #
     # logger.info("\"bancoy\" -> Authdecrypted \"Loan-Application-Basic\" Proof from nilo")
     # _, authdecrypted_nilo_apply_loan_proof_json, authdecrypted_nilo_apply_loan_proof = \
     #     await auth_decrypt(bancoy_wallet, bancoy_nilo_key, authcrypted_nilo_apply_loan_proof_json)
     #
     # logger.info("\"bancoy\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
     #             " required for Proof verifying")
     #
     # schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
     #     await verifier_get_entities_from_ledger(pool_handle, bancoy_did,
     #                                             authdecrypted_nilo_apply_loan_proof['identifiers'], 'bancoy')
     #
     # logger.info("\"bancoy\" -> Verify \"Loan-Application-Basic\" Proof from nilo")
     # assert 'Permanent' == \
     #        authdecrypted_nilo_apply_loan_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
     #
     # assert await anoncreds.verifier_verify_proof(apply_loan_proof_request_json,
     #                                              authdecrypted_nilo_apply_loan_proof_json,
     #                                              schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)
     #
     # logger.info("\"bancoy\" -> Create \"Loan-Application-KYC\" Proof Request")
     # apply_loan_kyc_proof_request_json = json.dumps({
     #     'nonce': '123432421212',
     #     'name': 'Loan-Application-KYC',
     #     'version': '0.1',
     #     'requested_attributes': {
     #         'attr1_referent': {'name': 'first_name'},
     #         'attr2_referent': {'name': 'last_name'},
     #         'attr3_referent': {'name': 'ssn'}
     #     },
     #     'requested_predicates': {}
     # })
     #
     # logger.info("\"bancoy\" -> Get key for nilo did")
     # nilo_bancoy_verkey = await did.key_for_did(pool_handle, bancoy_wallet, bancoy_nilo_connection_response['did'])
     #
     # logger.info("\"bancoy\" -> Authcrypt \"Loan-Application-KYC\" Proof Request for nilo")
     # authcrypted_apply_loan_kyc_proof_request_json = \
     #     await crypto.auth_crypt(bancoy_wallet, bancoy_nilo_key, nilo_bancoy_verkey,
     #                             apply_loan_kyc_proof_request_json.encode('utf-8'))
     #
     # logger.info("\"bancoy\" -> Send authcrypted \"Loan-Application-KYC\" Proof Request to nilo")
     #
     # logger.info("\"nilo\" -> Authdecrypt \"Loan-Application-KYC\" Proof Request from bancoy")
     # bancoy_nilo_verkey, authdecrypted_apply_loan_kyc_proof_request_json, _ = \
     #     await auth_decrypt(nilo_wallet, nilo_bancoy_key, authcrypted_apply_loan_kyc_proof_request_json)
     #
     # logger.info("\"nilo\" -> Get credentials for \"Loan-Application-KYC\" Proof Request")
     #
     # search_for_apply_loan_kyc_proof_request = \
     #     await anoncreds.prover_search_credentials_for_proof_req(nilo_wallet,
     #                                                             authdecrypted_apply_loan_kyc_proof_request_json, None)
     #
     # cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr1_referent')
     # cred_for_attr2 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr2_referent')
     # cred_for_attr3 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr3_referent')
     #
     # await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_kyc_proof_request)
     #
     # creds_for_apply_loan_kyc_proof = {cred_for_attr1['referent']: cred_for_attr1,
     #                                   cred_for_attr2['referent']: cred_for_attr2,
     #                                   cred_for_attr3['referent']: cred_for_attr3}
     #
     # schemas_json, cred_defs_json, revoc_states_json = \
     #     await prover_get_entities_from_ledger(pool_handle, nilo_bancoy_did, creds_for_apply_loan_kyc_proof, 'nilo')
     #
     # logger.info("\"nilo\" -> Create \"Loan-Application-KYC\" Proof")
     #
     # apply_loan_kyc_requested_creds_json = json.dumps({
     #     'self_attested_attributes': {},
     #     'requested_attributes': {
     #         'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
     #         'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
     #         'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
     #     },
     #     'requested_predicates': {}
     # })
     #
     # nilo_apply_loan_kyc_proof_json = \
     #     await anoncreds.prover_create_proof(nilo_wallet, authdecrypted_apply_loan_kyc_proof_request_json,
     #                                         apply_loan_kyc_requested_creds_json, nilo_master_secret_id,
     #                                         schemas_json, cred_defs_json, revoc_states_json)
     #
     # logger.info("\"nilo\" -> Authcrypt \"Loan-Application-KYC\" Proof for bancoy")
     # authcrypted_nilo_apply_loan_kyc_proof_json = \
     #     await crypto.auth_crypt(nilo_wallet, nilo_bancoy_key, bancoy_nilo_verkey,
     #                             nilo_apply_loan_kyc_proof_json.encode('utf-8'))
     #
     # logger.info("\"nilo\" -> Send authcrypted \"Loan-Application-KYC\" Proof to bancoy")
     #
     # logger.info("\"bancoy\" -> Authdecrypted \"Loan-Application-KYC\" Proof from nilo")
     # _, authdecrypted_nilo_apply_loan_kyc_proof_json, authdecrypted_nilo_apply_loan_kyc_proof = \
     #     await auth_decrypt(bancoy_wallet, bancoy_nilo_key, authcrypted_nilo_apply_loan_kyc_proof_json)
     #
     # logger.info("\"bancoy\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
     #             " required for Proof verifying")
     #
     # schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
     #     await verifier_get_entities_from_ledger(pool_handle, bancoy_did,
     #                                             authdecrypted_nilo_apply_loan_kyc_proof['identifiers'], 'bancoy')
     #
     # logger.info("\"bancoy\" -> Verify \"Loan-Application-KYC\" Proof from nilo")
     # assert 'nilo' == \
     #        authdecrypted_nilo_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
     # assert 'mendonca' == \
     #        authdecrypted_nilo_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
     # assert '123-45-6789' == \
     #        authdecrypted_nilo_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
     #
     # # assert await anoncreds.verifier_verify_proof(apply_loan_kyc_proof_request_json,
     # #                                              authdecrypted_nilo_apply_loan_kyc_proof_json,
     # #                                              schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)


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
