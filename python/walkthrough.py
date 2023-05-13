import time

from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
import logging
import os
from typing import Optional

from indy.error import ErrorCode, IndyError

from src.utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION
import subprocess
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def run():
     bashCommand = "bash refresh.sh"
     process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
     output, error = process.communicate()
     os.system('clear')
     logger.info("Seta as configuracoes iniciais do bloco genesis e conexao no pool")

     pool_name = 'pool1'
     logger.info("Open Pool Ledger: {}".format(pool_name))
     pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
     pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})
     print(pool_config)

     input("\n\n\n\n\ncontinuar?")

     # Set protocol version 2 to work with Indy Node 1.4
     await pool.set_protocol_version(PROTOCOL_VERSION)

     try:
         await pool.create_pool_ledger_config(pool_name, pool_config)
     except IndyError as ex:
         if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
             pass
     pool_handle = await pool.open_pool_ledger(pool_name, None)

     logger.info("==============================")
     logger.info("=== Obtem as credenciais de Identificador descentralizado para Unb, EmpresaX, bancoy e governo  ==")
     logger.info("------------------------------")

     logger.info("\"Admin do Ledge (Trust Anchor) \" -> Criacao da carteira")
     admin_wallet_config = json.dumps({"id": "admin_wallet"})
     admin_wallet_credentials = json.dumps({"key": "admin_wallet_key"})
     try:
         await wallet.create_wallet(admin_wallet_config, admin_wallet_credentials)
     except IndyError as ex:
         if ex.error_code == ErrorCode.WalletAlreadyExistsError:
             pass

     admin_wallet = await wallet.open_wallet(admin_wallet_config, admin_wallet_credentials)

     logger.info("\"Admin do Ledge\" -> Criacao e armazenamento do DID na carteira")
     admin_did_info = {'seed': '000000000000000000000000Steward1'}
     (admin_did, admin_key) = await did.create_and_store_my_did(admin_wallet, json.dumps(admin_did_info))

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("== Gerando credenciais de Trust Anchor - governo  ==")
     logger.info("------------------------------")

     governo_wallet_config = json.dumps({"id": "governo_wallet"})
     governo_wallet_credentials = json.dumps({"key": "governo_wallet_key"})
     governo_wallet, admin_governo_key, governo_admin_did, governo_admin_key, _ \
         = await onboarding(pool_handle, "Admin", admin_wallet, admin_did, "governo", None,
                            governo_wallet_config, governo_wallet_credentials)

     governo_did = await get_verinym(pool_handle, "Admin", admin_wallet, admin_did,
                                        admin_governo_key, "governo", governo_wallet, governo_admin_did,
                                        governo_admin_key, 'TRUST_ANCHOR')

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("== Gerando credenciais de Trust Anchor - UNB  ==")
     logger.info("------------------------------")

     unb_wallet_config = json.dumps({"id": "unb_wallet"})
     unb_wallet_credentials = json.dumps({"key": "unb_wallet_key"})
     unb_wallet, admin_unb_key, unb_admin_did, unb_admin_key, _ = \
         await onboarding(pool_handle, "Admin", admin_wallet, admin_did, "Unb", None, unb_wallet_config,
                          unb_wallet_credentials)

     unb_did = await get_verinym(pool_handle, "Admin", admin_wallet, admin_did, admin_unb_key,
                                   "Unb", unb_wallet, unb_admin_did, unb_admin_key, 'TRUST_ANCHOR')

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("== Gerando credenciais de Trust Anchor - Empresa X  ==")
     logger.info("------------------------------")

     empresax_wallet_config = json.dumps({"id": "empresax_wallet"})
     empresax_wallet_credentials = json.dumps({"key": "empresax_wallet_key"})
     empresax_wallet, admin_empresax_key, empresax_admin_did, empresax_admin_key, _ = \
         await onboarding(pool_handle, "Admin", admin_wallet, admin_did, "empresax", None, empresax_wallet_config,
                          empresax_wallet_credentials)

     empresax_did = await get_verinym(pool_handle, "Admin", admin_wallet, admin_did, admin_empresax_key,
                                  "empresax", empresax_wallet, empresax_admin_did, empresax_admin_key, 'TRUST_ANCHOR')

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("== Gerando credenciais de Trust Anchor - banco Y  ==")
     logger.info("------------------------------")

     bancoy_wallet_config = json.dumps({"id": " bancoy_wallet"})
     bancoy_wallet_credentials = json.dumps({"key": "bancoy_wallet_key"})
     bancoy_wallet, admin_bancoy_key, bancoy_admin_did, bancoy_admin_key, _ = \
         await onboarding(pool_handle, "Admin", admin_wallet, admin_did, "bancoy", None,
                          bancoy_wallet_config, bancoy_wallet_credentials)

     bancoy_did = await get_verinym(pool_handle, "Admin", admin_wallet, admin_did, admin_bancoy_key,
                                    "bancoy", bancoy_wallet, bancoy_admin_did, bancoy_admin_key, 'TRUST_ANCHOR')

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("=== Criacao dos schemas ==")
     logger.info("------------------------------")

     logger.info("\"unb\" -> Create \"Job-Certificate\" Schema")
     (job_certificate_schema_id, job_certificate_schema) = \
         await anoncreds.issuer_create_schema(governo_did, 'Job-Certificate', '0.2',
                                              json.dumps(['first_name', 'last_name', 'salary', 'employee_status',
                                                          'experience']))

     logger.info("\"governo\" -> Send \"Job-Certificate\" Schema to Ledger")
     await send_schema(pool_handle, governo_wallet, governo_did, job_certificate_schema)

     logger.info("\"governo\" -> Create \"Transcript\" Schema")
     (transcript_schema_id, transcript_schema) = \
         await anoncreds.issuer_create_schema(governo_did, 'Transcript', '1.2',
                                              json.dumps(['first_name', 'last_name', 'degree', 'status',
                                                          'year', 'average', 'ssn']))
     logger.info("\"governo\" -> Send \"Transcript\" Schema to Ledger")
     await send_schema(pool_handle, governo_wallet, governo_did, transcript_schema)

     time.sleep(1)  # sleep 1 second before getting schema

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("=== Definicao das credenciais da UNB ==")
     logger.info("------------------------------")

     logger.info("\"Unb\" -> Get \"Transcript\" Schema from Ledger")
     (_, transcript_schema) = await get_schema(pool_handle, unb_did, transcript_schema_id)

     logger.info("\"Unb\" -> Create and store in Wallet \"Unb Transcript\" Credential Definition")
     (unb_transcript_cred_def_id, unb_transcript_cred_def_json) = \
         await anoncreds.issuer_create_and_store_credential_def(unb_wallet, unb_did, transcript_schema,
                                                                'TAG1', 'CL', '{"support_revocation": false}')

     logger.info("\"Unb\" -> Send  \"Unb Transcript\" Credential Definition to Ledger")
     await send_cred_def(pool_handle, unb_wallet, unb_did, unb_transcript_cred_def_json)

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("=== definicao das credenciais da empresa X ==")
     logger.info("------------------------------")

     logger.info("\"empresax\" -> Get from Ledger \"Job-Certificate\" Schema")
     (_, job_certificate_schema) = await get_schema(pool_handle, empresax_did, job_certificate_schema_id)

     logger.info("\"empresax\" -> Create and store in Wallet \"empresax Job-Certificate\" Credential Definition")
     (empresax_job_certificate_cred_def_id, empresax_job_certificate_cred_def_json) = \
         await anoncreds.issuer_create_and_store_credential_def(empresax_wallet, empresax_did, job_certificate_schema,
                                                                'TAG1', 'CL', '{"support_revocation": false}')

     logger.info("\"empresax\" -> Send \"empresax Job-Certificate\" Credential Definition to Ledger")
     await send_cred_def(pool_handle, empresax_wallet, empresax_did, empresax_job_certificate_cred_def_json)

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("==============================")
     logger.info("== Geracao das credenciais da Unb para emitir atestado de formado ==")
     logger.info("------------------------------")

     nilo_wallet_config = json.dumps({"id": " nilo_wallet"})
     nilo_wallet_credentials = json.dumps({"key": "nilo_wallet_key"})
     nilo_wallet, unb_nilo_key, nilo_unb_did, nilo_unb_key, unb_nilo_connection_response \
         = await onboarding(pool_handle, "Unb", unb_wallet, unb_did, "nilo", None, nilo_wallet_config,
                            nilo_wallet_credentials)

     logger.info("\"Unb\" -> Create \"Transcript\" Credential Offer for nilo")
     transcript_cred_offer_json = \
         await anoncreds.issuer_create_credential_offer(unb_wallet, unb_transcript_cred_def_id)

     logger.info("\"Unb\" -> Get key for nilo did")
     nilo_unb_verkey = await did.key_for_did(pool_handle, empresax_wallet, unb_nilo_connection_response['did'])

     logger.info("\"Unb\" -> Authcrypt \"Transcript\" Credential Offer for nilo")
     authcrypted_transcript_cred_offer = await crypto.auth_crypt(unb_wallet, unb_nilo_key, nilo_unb_verkey,
                                                                 transcript_cred_offer_json.encode('utf-8'))

     logger.info("\"Unb\" -> Send authcrypted \"Transcript\" Credential Offer to nilo")

     logger.info("\"nilo\" -> Authdecrypted \"Transcript\" Credential Offer from unb")
     unb_nilo_verkey, authdecrypted_transcript_cred_offer_json, authdecrypted_transcript_cred_offer = \
         await auth_decrypt(nilo_wallet, nilo_unb_key, authcrypted_transcript_cred_offer)

     logger.info("\"nilo\" -> Create and store \"nilo\" Master Secret in Wallet")
     nilo_master_secret_id = await anoncreds.prover_create_master_secret(nilo_wallet, None)

     logger.info("\"nilo\" -> Get \"unb Transcript\" Credential Definition from Ledger")
     (unb_transcript_cred_def_id, unb_transcript_cred_def) = \
         await get_cred_def(pool_handle, nilo_unb_did, authdecrypted_transcript_cred_offer['cred_def_id'])

     logger.info("\"nilo\" -> Create \"Transcript\" Credential Request for unb")
     (transcript_cred_request_json, transcript_cred_request_metadata_json) = \
         await anoncreds.prover_create_credential_req(nilo_wallet, nilo_unb_did,
                                                      authdecrypted_transcript_cred_offer_json,
                                                      unb_transcript_cred_def, nilo_master_secret_id)

     logger.info("\"nilo\" -> Authcrypt \"Transcript\" Credential Request for unb")
     authcrypted_transcript_cred_request = await crypto.auth_crypt(nilo_wallet, nilo_unb_key, unb_nilo_verkey,
                                                                   transcript_cred_request_json.encode('utf-8'))

     logger.info("\"nilo\" -> Send authcrypted \"Transcript\" Credential Request to unb")

     logger.info("\"unb\" -> Authdecrypt \"Transcript\" Credential Request from nilo")
     nilo_unb_verkey, authdecrypted_transcript_cred_request_json, _ = \
         await auth_decrypt(unb_wallet, unb_nilo_key, authcrypted_transcript_cred_request)

     logger.info("\"unb\" -> Create \"Transcript\" Credential for nilo")
     transcript_cred_values = json.dumps({
         "first_name": {"raw": "nilo", "encoded": "1139481716457488690172217916278103335"},
         "last_name": {"raw": "mendonca", "encoded": "5321642780241790123587902456789123452"},
         "degree": {"raw": "bacharelado, engenharia de software", "encoded": "12434523576212321"},
         "status": {"raw": "graduacao", "encoded": "2213454313412354"},
         "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
         "year": {"raw": "2023", "encoded": "2015"},
         "average": {"raw": "5", "encoded": "5"}
     })

     transcript_cred_json, _, _ = \
         await anoncreds.issuer_create_credential(unb_wallet, transcript_cred_offer_json,
                                                  authdecrypted_transcript_cred_request_json,
                                                  transcript_cred_values, None, None)

     logger.info("\"unb\" -> Authcrypt \"Transcript\" Credential for nilo")
     authcrypted_transcript_cred_json = await crypto.auth_crypt(unb_wallet, unb_nilo_key, nilo_unb_verkey,
                                                                transcript_cred_json.encode('utf-8'))

     logger.info("\"unb\" -> Send authcrypted \"Transcript\" Credential to nilo")

     logger.info("\"nilo\" -> Authdecrypted \"Transcript\" Credential from unb")
     _, authdecrypted_transcript_cred_json, _ = \
         await auth_decrypt(nilo_wallet, nilo_unb_key, authcrypted_transcript_cred_json)

     logger.info("\"nilo\" -> Store \"Transcript\" Credential from unb")
     await anoncreds.prover_store_credential(nilo_wallet, None, transcript_cred_request_metadata_json,
                                             authdecrypted_transcript_cred_json, unb_transcript_cred_def, None)

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("==============================")
     logger.info("== Verificacao de vinculo com a Unb e ==")
     logger.info("== Geracao das credenciais da Empresa X para emitir atestado de vinculo ==")
     logger.info("------------------------------")

     nilo_wallet, empresax_nilo_key, nilo_empresax_did, nilo_empresax_key, empresax_nilo_connection_response = \
         await onboarding(pool_handle, "empresax", empresax_wallet, empresax_did, "nilo", nilo_wallet, nilo_wallet_config,
                          nilo_wallet_credentials)

     logger.info("\"empresax\" -> Create \"Job-Application\" Proof Request")
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
                 'restrictions': [{'cred_def_id': unb_transcript_cred_def_id}]
             },
             'attr4_referent': {
                 'name': 'status',
                 'restrictions': [{'cred_def_id': unb_transcript_cred_def_id}]
             },
             'attr5_referent': {
                 'name': 'ssn',
                 'restrictions': [{'cred_def_id': unb_transcript_cred_def_id}]
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
                 'restrictions': [{'cred_def_id': unb_transcript_cred_def_id}]
             }
         }
     })

     logger.info("\"empresax\" -> Get key for nilo did")
     nilo_empresax_verkey = await did.key_for_did(pool_handle, empresax_wallet, empresax_nilo_connection_response['did'])

     logger.info("\"empresax\" -> Authcrypt \"Job-Application\" Proof Request for nilo")
     authcrypted_job_application_proof_request_json = \
         await crypto.auth_crypt(empresax_wallet, empresax_nilo_key, nilo_empresax_verkey,
                                 job_application_proof_request_json.encode('utf-8'))

     logger.info("\"empresax\" -> Send authcrypted \"Job-Application\" Proof Request to nilo")

     logger.info("\"nilo\" -> Authdecrypt \"Job-Application\" Proof Request from empresax")
     empresax_nilo_verkey, authdecrypted_job_application_proof_request_json, _ = \
         await auth_decrypt(nilo_wallet, nilo_empresax_key, authcrypted_job_application_proof_request_json)

     logger.info("\"nilo\" -> Get credentials for \"Job-Application\" Proof Request")

     search_for_job_application_proof_request = \
         await anoncreds.prover_search_credentials_for_proof_req(nilo_wallet,
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
         await prover_get_entities_from_ledger(pool_handle, nilo_unb_did, creds_for_job_application_proof, 'nilo')

     logger.info("\"nilo\" -> Create \"Job-Application\" Proof")
     job_application_requested_creds_json = json.dumps({
         'self_attested_attributes': {
             'attr1_referent': 'nilo',
             'attr2_referent': 'mendonca',
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
         await anoncreds.prover_create_proof(nilo_wallet, authdecrypted_job_application_proof_request_json,
                                             job_application_requested_creds_json, nilo_master_secret_id,
                                             schemas_json, cred_defs_json, revoc_states_json)

     logger.info("\"nilo\" -> Authcrypt \"Job-Application\" Proof for empresax")
     authcrypted_job_application_proof_json = await crypto.auth_crypt(nilo_wallet, nilo_empresax_key, empresax_nilo_verkey,
                                                                      job_application_proof_json.encode('utf-8'))

     logger.info("\"nilo\" -> Send authcrypted \"Job-Application\" Proof to empresax")

     logger.info("\"empresax\" -> Authdecrypted \"Job-Application\" Proof from nilo")
     _, decrypted_job_application_proof_json, decrypted_job_application_proof = \
         await auth_decrypt(empresax_wallet, empresax_nilo_key, authcrypted_job_application_proof_json)

     schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json = \
         await verifier_get_entities_from_ledger(pool_handle, empresax_did,
                                                 decrypted_job_application_proof['identifiers'], 'empresax')

     logger.info("\"empresax\" -> Verify \"Job-Application\" Proof from nilo")
     assert 'bacharelado, engenharia de software' == \
            decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
     assert 'graduacao' == \
            decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
     assert '123-45-6789' == \
            decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

     assert 'nilo' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
     assert 'mendonca' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
     assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

     assert await anoncreds.verifier_verify_proof(job_application_proof_request_json,
                                                  decrypted_job_application_proof_json,
                                                  schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json)

     logger.info("\"empresax\" -> Create \"Job-Certificate\" Credential Offer for nilo")
     job_certificate_cred_offer_json = \
         await anoncreds.issuer_create_credential_offer(empresax_wallet, empresax_job_certificate_cred_def_id)

     logger.info("\"empresax\" -> Get key for nilo did")
     nilo_empresax_verkey = await did.key_for_did(pool_handle, empresax_wallet, empresax_nilo_connection_response['did'])

     logger.info("\"empresax\" -> Authcrypt \"Job-Certificate\" Credential Offer for nilo")
     authcrypted_job_certificate_cred_offer = await crypto.auth_crypt(empresax_wallet, empresax_nilo_key, nilo_empresax_verkey,
                                                                      job_certificate_cred_offer_json.encode('utf-8'))

     logger.info("\"empresax\" -> Send authcrypted \"Job-Certificate\" Credential Offer to nilo")

     logger.info("\"nilo\" -> Authdecrypted \"Job-Certificate\" Credential Offer from empresax")
     empresax_nilo_verkey, authdecrypted_job_certificate_cred_offer_json, authdecrypted_job_certificate_cred_offer = \
         await auth_decrypt(nilo_wallet, nilo_empresax_key, authcrypted_job_certificate_cred_offer)

     logger.info("\"nilo\" -> Get \"empresax Job-Certificate\" Credential Definition from Ledger")
     (_, empresax_job_certificate_cred_def) = \
         await get_cred_def(pool_handle, nilo_empresax_did, authdecrypted_job_certificate_cred_offer['cred_def_id'])

     logger.info("\"nilo\" -> Create and store in Wallet \"Job-Certificate\" Credential Request for empresax")
     (job_certificate_cred_request_json, job_certificate_cred_request_metadata_json) = \
         await anoncreds.prover_create_credential_req(nilo_wallet, nilo_empresax_did,
                                                      authdecrypted_job_certificate_cred_offer_json,
                                                      empresax_job_certificate_cred_def, nilo_master_secret_id)

     logger.info("\"nilo\" -> Authcrypt \"Job-Certificate\" Credential Request for empresax")
     authcrypted_job_certificate_cred_request_json = \
         await crypto.auth_crypt(nilo_wallet, nilo_empresax_key, empresax_nilo_verkey,
                                 job_certificate_cred_request_json.encode('utf-8'))

     logger.info("\"nilo\" -> Send authcrypted \"Job-Certificate\" Credential Request to empresax")

     logger.info("\"empresax\" -> Authdecrypt \"Job-Certificate\" Credential Request from nilo")
     nilo_empresax_verkey, authdecrypted_job_certificate_cred_request_json, _ = \
         await auth_decrypt(empresax_wallet, empresax_nilo_key, authcrypted_job_certificate_cred_request_json)

     logger.info("\"empresax\" -> Create \"Job-Certificate\" Credential for nilo")
     nilo_job_certificate_cred_values_json = json.dumps({
         "first_name": {"raw": "nilo", "encoded": "245712572474217942457235975012103335"},
         "last_name": {"raw": "mendonca", "encoded": "312643218496194691632153761283356127"},
         "employee_status": {"raw": "Permanent", "encoded": "2143135425425143112321314321"},
         "salary": {"raw": "2400", "encoded": "2400"},
         "experience": {"raw": "10", "encoded": "10"}
     })

     job_certificate_cred_json, _, _ = \
         await anoncreds.issuer_create_credential(empresax_wallet, job_certificate_cred_offer_json,
                                                  authdecrypted_job_certificate_cred_request_json,
                                                  nilo_job_certificate_cred_values_json, None, None)

     logger.info("\"empresax\" -> Authcrypt \"Job-Certificate\" Credential for nilo")
     authcrypted_job_certificate_cred_json = \
         await crypto.auth_crypt(empresax_wallet, empresax_nilo_key, nilo_empresax_verkey,
                                 job_certificate_cred_json.encode('utf-8'))

     logger.info("\"empresax\" -> Send authcrypted \"Job-Certificate\" Credential to nilo")

     logger.info("\"nilo\" -> Authdecrypted \"Job-Certificate\" Credential from empresax")
     _, authdecrypted_job_certificate_cred_json, _ = \
         await auth_decrypt(nilo_wallet, nilo_empresax_key, authcrypted_job_certificate_cred_json)

     logger.info("\"nilo\" -> Store \"Job-Certificate\" Credential")
     await anoncreds.prover_store_credential(nilo_wallet, None, job_certificate_cred_request_metadata_json,
                                             authdecrypted_job_certificate_cred_json,
                                             empresax_job_certificate_cred_def_json, None)

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("== Verificacao das credenciais de trabalho na empresa X ==")
     logger.info("------------------------------")

     _, bancoy_nilo_key, nilo_bancoy_did, nilo_bancoy_key, \
     bancoy_nilo_connection_response = await onboarding(pool_handle, "bancoy", bancoy_wallet, bancoy_did, "nilo",
                                                         nilo_wallet, nilo_wallet_config, nilo_wallet_credentials)

     logger.info("\"bancoy\" -> Create \"Loan-Application-Basic\" Proof Request")
     apply_loan_proof_request_json = json.dumps({
         'nonce': '123432421212',
         'name': 'Loan-Application-Basic',
         'version': '0.1',
         'requested_attributes': {
             'attr1_referent': {
                 'name': 'employee_status',
                 'restrictions': [{'cred_def_id': empresax_job_certificate_cred_def_id}]
             }
         },
         'requested_predicates': {
             'predicate1_referent': {
                 'name': 'salary',
                 'p_type': '>=',
                 'p_value': 2000,
                 'restrictions': [{'cred_def_id': empresax_job_certificate_cred_def_id}]
             },
             'predicate2_referent': {
                 'name': 'experience',
                 'p_type': '>=',
                 'p_value': 1,
                 'restrictions': [{'cred_def_id': empresax_job_certificate_cred_def_id}]
             }
         }
     })

     logger.info("\"bancoy\" -> Get key for nilo did")
     nilo_bancoy_verkey = await did.key_for_did(pool_handle, bancoy_wallet, bancoy_nilo_connection_response['did'])

     logger.info("\"bancoy\" -> Authcrypt \"Loan-Application-Basic\" Proof Request for nilo")
     authcrypted_apply_loan_proof_request_json = \
         await crypto.auth_crypt(bancoy_wallet, bancoy_nilo_key, nilo_bancoy_verkey,
                                 apply_loan_proof_request_json.encode('utf-8'))

     logger.info("\"bancoy\" -> Send authcrypted \"Loan-Application-Basic\" Proof Request to nilo")

     logger.info("\"nilo\" -> Authdecrypt \"Loan-Application-Basic\" Proof Request from bancoy")
     bancoy_nilo_verkey, authdecrypted_apply_loan_proof_request_json, _ = \
         await auth_decrypt(nilo_wallet, nilo_bancoy_key, authcrypted_apply_loan_proof_request_json)

     logger.info("\"nilo\" -> Get credentials for \"Loan-Application-Basic\" Proof Request")

     search_for_apply_loan_proof_request = \
         await anoncreds.prover_search_credentials_for_proof_req(nilo_wallet,
                                                                 authdecrypted_apply_loan_proof_request_json, None)

     cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'attr1_referent')
     cred_for_predicate1 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate1_referent')
     cred_for_predicate2 = await get_credential_for_referent(search_for_apply_loan_proof_request, 'predicate2_referent')

     await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_proof_request)

     creds_for_apply_loan_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                   cred_for_predicate1['referent']: cred_for_predicate1,
                                   cred_for_predicate2['referent']: cred_for_predicate2}

     schemas_json, cred_defs_json, revoc_states_json = \
         await prover_get_entities_from_ledger(pool_handle, nilo_bancoy_did, creds_for_apply_loan_proof, 'nilo')

     logger.info("\"nilo\" -> Create \"Loan-Application-Basic\" Proof")
     apply_loan_requested_creds_json = json.dumps({
         'self_attested_attributes': {},
         'requested_attributes': {
             'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True}
         },
         'requested_predicates': {
             'predicate1_referent': {'cred_id': cred_for_predicate1['referent']},
             'predicate2_referent': {'cred_id': cred_for_predicate2['referent']}
         }
     })
     nilo_apply_loan_proof_json = \
         await anoncreds.prover_create_proof(nilo_wallet, authdecrypted_apply_loan_proof_request_json,
                                             apply_loan_requested_creds_json, nilo_master_secret_id, schemas_json,
                                             cred_defs_json, revoc_states_json)

     logger.info("\"nilo\" -> Authcrypt \"Loan-Application-Basic\" Proof for bancoy")
     authcrypted_nilo_apply_loan_proof_json = \
         await crypto.auth_crypt(nilo_wallet, nilo_bancoy_key, bancoy_nilo_verkey,
                                 nilo_apply_loan_proof_json.encode('utf-8'))

     logger.info("\"nilo\" -> Send authcrypted \"Loan-Application-Basic\" Proof to bancoy")

     logger.info("\"bancoy\" -> Authdecrypted \"Loan-Application-Basic\" Proof from nilo")
     _, authdecrypted_nilo_apply_loan_proof_json, authdecrypted_nilo_apply_loan_proof = \
         await auth_decrypt(bancoy_wallet, bancoy_nilo_key, authcrypted_nilo_apply_loan_proof_json)

     logger.info("\"bancoy\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                 " required for Proof verifying")

     schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
         await verifier_get_entities_from_ledger(pool_handle, bancoy_did,
                                                 authdecrypted_nilo_apply_loan_proof['identifiers'], 'bancoy')

     logger.info("\"bancoy\" -> Verify \"Loan-Application-Basic\" Proof from nilo")
     assert 'Permanent' == \
            authdecrypted_nilo_apply_loan_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

     assert await anoncreds.verifier_verify_proof(apply_loan_proof_request_json,
                                                  authdecrypted_nilo_apply_loan_proof_json,
                                                  schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

     logger.info("\"bancoy\" -> Create \"Loan-Application-KYC\" Proof Request")
     apply_loan_kyc_proof_request_json = json.dumps({
         'nonce': '123432421212',
         'name': 'Loan-Application-KYC',
         'version': '0.1',
         'requested_attributes': {
             'attr1_referent': {'name': 'first_name'},
             'attr2_referent': {'name': 'last_name'},
             'attr3_referent': {'name': 'ssn'}
         },
         'requested_predicates': {}
     })

     logger.info("\"bancoy\" -> Get key for nilo did")
     nilo_bancoy_verkey = await did.key_for_did(pool_handle, bancoy_wallet, bancoy_nilo_connection_response['did'])

     logger.info("\"bancoy\" -> Authcrypt \"Loan-Application-KYC\" Proof Request for nilo")
     authcrypted_apply_loan_kyc_proof_request_json = \
         await crypto.auth_crypt(bancoy_wallet, bancoy_nilo_key, nilo_bancoy_verkey,
                                 apply_loan_kyc_proof_request_json.encode('utf-8'))

     logger.info("\"bancoy\" -> Send authcrypted \"Loan-Application-KYC\" Proof Request to nilo")

     logger.info("\"nilo\" -> Authdecrypt \"Loan-Application-KYC\" Proof Request from bancoy")
     bancoy_nilo_verkey, authdecrypted_apply_loan_kyc_proof_request_json, _ = \
         await auth_decrypt(nilo_wallet, nilo_bancoy_key, authcrypted_apply_loan_kyc_proof_request_json)

     logger.info("\"nilo\" -> Get credentials for \"Loan-Application-KYC\" Proof Request")

     search_for_apply_loan_kyc_proof_request = \
         await anoncreds.prover_search_credentials_for_proof_req(nilo_wallet,
                                                                 authdecrypted_apply_loan_kyc_proof_request_json, None)

     cred_for_attr1 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr1_referent')
     cred_for_attr2 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr2_referent')
     cred_for_attr3 = await get_credential_for_referent(search_for_apply_loan_kyc_proof_request, 'attr3_referent')

     await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_loan_kyc_proof_request)

     creds_for_apply_loan_kyc_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                       cred_for_attr2['referent']: cred_for_attr2,
                                       cred_for_attr3['referent']: cred_for_attr3}

     schemas_json, cred_defs_json, revoc_states_json = \
         await prover_get_entities_from_ledger(pool_handle, nilo_bancoy_did, creds_for_apply_loan_kyc_proof, 'nilo')

     logger.info("\"nilo\" -> Create \"Loan-Application-KYC\" Proof")

     apply_loan_kyc_requested_creds_json = json.dumps({
         'self_attested_attributes': {},
         'requested_attributes': {
             'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True},
             'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True},
             'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True}
         },
         'requested_predicates': {}
     })

     nilo_apply_loan_kyc_proof_json = \
         await anoncreds.prover_create_proof(nilo_wallet, authdecrypted_apply_loan_kyc_proof_request_json,
                                             apply_loan_kyc_requested_creds_json, nilo_master_secret_id,
                                             schemas_json, cred_defs_json, revoc_states_json)

     logger.info("\"nilo\" -> Authcrypt \"Loan-Application-KYC\" Proof for bancoy")
     authcrypted_nilo_apply_loan_kyc_proof_json = \
         await crypto.auth_crypt(nilo_wallet, nilo_bancoy_key, bancoy_nilo_verkey,
                                 nilo_apply_loan_kyc_proof_json.encode('utf-8'))

     logger.info("\"nilo\" -> Send authcrypted \"Loan-Application-KYC\" Proof to bancoy")

     logger.info("\"bancoy\" -> Authdecrypted \"Loan-Application-KYC\" Proof from nilo")
     _, authdecrypted_nilo_apply_loan_kyc_proof_json, authdecrypted_nilo_apply_loan_kyc_proof = \
         await auth_decrypt(bancoy_wallet, bancoy_nilo_key, authcrypted_nilo_apply_loan_kyc_proof_json)

     logger.info("\"bancoy\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                 " required for Proof verifying")

     schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
         await verifier_get_entities_from_ledger(pool_handle, bancoy_did,
                                                 authdecrypted_nilo_apply_loan_kyc_proof['identifiers'], 'bancoy')

     logger.info("\"bancoy\" -> Verify \"Loan-Application-KYC\" Proof from nilo")
     assert 'nilo' == \
            authdecrypted_nilo_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']
     assert 'mendonca' == \
            authdecrypted_nilo_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr2_referent']['raw']
     assert '123-45-6789' == \
            authdecrypted_nilo_apply_loan_kyc_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']

     # assert await anoncreds.verifier_verify_proof(apply_loan_kyc_proof_request_json,
     #                                              authdecrypted_nilo_apply_loan_kyc_proof_json,
     #                                              schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)

     input("\n\n\n\n\ncontinuar?")

     logger.info("==============================")
     logger.info("== exclui as carteiras e encerra a aplicacao ==")
     logger.info("==============================")

     logger.info(" \"Admin\" -> Fecha e exclui carteira")
     await wallet.close_wallet(admin_wallet)
     await wallet.delete_wallet(admin_wallet_config, admin_wallet_credentials)

     logger.info("\"governo\" -> Close and Delete wallet")
     await wallet.close_wallet(governo_wallet)
     await wallet.delete_wallet(governo_wallet_config, governo_wallet_credentials)

     logger.info("\"unb\" -> Close and Delete wallet")
     await wallet.close_wallet(unb_wallet)
     await wallet.delete_wallet(unb_wallet_config, unb_wallet_credentials)

     logger.info("\"empresax\" -> Close and Delete wallet")
     await wallet.close_wallet(empresax_wallet)
     await wallet.delete_wallet(empresax_wallet_config, empresax_wallet_credentials)

     logger.info("\"bancoy\" -> Close and Delete wallet")
     await wallet.close_wallet(bancoy_wallet)
     await wallet.delete_wallet(bancoy_wallet_config, bancoy_wallet_credentials)

     logger.info("\"nilo\" -> Close and Delete wallet")
     await wallet.close_wallet(nilo_wallet)
     await wallet.delete_wallet(nilo_wallet_config, nilo_wallet_credentials)

     logger.info("Close and Delete pool")
     await pool.close_pool_ledger(pool_handle)
     await pool.delete_pool_ledger_config(pool_name)

     logger.info("Getting started -> done")


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


if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete
