"""
This sample is extensions of "write_schema_and_cred_def.py"

Shows how to issue a credential as a Trust Anchor which has created a Cred Definition
for an existing Schema.

After Trust Anchor has successfully created and stored a Cred Definition using Anonymous Credentials,
Prover's wallet is created and opened, and used to generate Prover's Master Secret.
After that, Trust Anchor generates Credential Offer for given Cred Definition, using Prover's DID
Prover uses Credential Offer to create Credential Request
Trust Anchor then uses Prover's Credential Request to issue a Credential.
Finally, Prover stores Credential in its wallet.

trust anchor sao os unicos que podem escrever did (issuers)
"""


import asyncio
import json
import pprint
import sys
from typing import Optional

from src.utils import run_coroutine, get_pool_genesis_txn_path, PROTOCOL_VERSION

from indy import pool, ledger, wallet, did, anoncreds, crypto
from indy.error import IndyError, ErrorCode

from agent import Steward, Issuer, Holder

seq_no = 1
pool_name = 'pool'
wallet_credentials = json.dumps({"key": "wallet_key"})
steward_wallet_config = json.dumps({"id": "steward_wallet"})
issuer_wallet_config = json.dumps({"id": "issuer_wallet"})
pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})


def print_log(value_color="", value_noncolor=""):
    """set the colors for text."""
    HEADER = '\033[92m'
    ENDC = '\033[0m'
    print(HEADER + value_color + ENDC + str(value_noncolor))



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


async def pool_genesys(protocol_version, pool_name, pool_config):
    # Set protocol version 2 to work with Indy Node 1.4
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


async def issue_credential():
    pool_handle = await pool_genesys(PROTOCOL_VERSION, pool_name=pool_name, pool_config=pool_config)
    steward = Steward()
    issuer = Issuer()
    await steward.create(pool_handle, steward_wallet_config, wallet_credentials)
    await issuer.create(pool_handle, issuer_wallet_config, wallet_credentials)



    await steward.simple_onboarding(issuer.did, issuer.verkey, issuer.role)

    schema_id = await steward.new_schema('RegistroPaciente',  
                    ['name', 'phone', 'gender', \
                    'dateOfBirth', 'address', 'maritalStatus', \
                    'multipleBirth', 'contactRelationship', 'contactName', \
                    'contactPhone', 'contactAddress', 'contactGender', \
                    'languages', 'preferredLanguage', 'generalPractitioner',])
    
    prover = Holder()
    await prover.create(pool_handle, json.dumps({"id": "prover_wallet"}), json.dumps({"key": "prover_wallet_key"}))

    cred_def_id = await issuer.new_cred_def(schema_id)
    cred_offer_json = await issuer.new_cred_offer(cred_def_id)

    (cred_req_json, cred_req_metadata_json) = await prover.offer_to_cred_request(cred_offer_json, cred_def_id)

    cred_values_json = json.dumps({
        'name': {'raw': 'matheus', 'encoded': '12345'}, 'phone': {'raw': '61912341234', 'encoded': '12345'}, 'gender': {'raw': 'm', 'encoded': '12345'}, \
        'dateOfBirth': {'raw': '01011999', 'encoded': '12345'}, 'address':{'raw': 'Brasilia', 'encoded': '12345'}, 'maritalStatus': {'raw': 'abc', 'encoded': '12345'}, \
        'multipleBirth': {'raw': '0', 'encoded': '12345'}, 'contactRelationship': {'raw': 'a', 'encoded': '12345'}, 'contactName': {'raw': 'mamama', 'encoded': '12345'}, \
        'contactPhone': {'raw': '61901011010', 'encoded': '12345'}, 'contactAddress': {'raw': 'Brasilia', 'encoded': '12345'}, 'contactGender': {'raw': 'm', 'encoded': '12345'}, \
        'languages': {'raw': 'pt', 'encoded': '12345'}, 'preferredLanguage': {'raw': 'pt', 'encoded': '12345'}, 'generalPractitioner': {'raw': 'abccba', 'encoded': '12345'},
    })

    cred_json = await issuer.request_to_cred_issue(cred_offer_json, cred_req_json, cred_values_json)

    await prover.store_ver_cred(cred_req_metadata_json, cred_json, cred_def_id)

#H47E8utjt5jUEcFisMh5Ti:3:CL:12:cred_def_tag
#H47E8utjt5jUEcFisMh5Ti:3:CL:12:cred_def_tag
    await issuer.delete()    
    await prover.delete()    

    try:
        # 20.
        print_log('\n20. Close and Deleting pool ledger config\n')
        await pool.close_pool_ledger(pool_handle)
        await pool.delete_pool_ledger_config(pool_name)
    except IndyError as e:
            print('Error occurred: %s' % e)
    


def main():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(issue_credential())
    loop.close()


if __name__ == '__main__':
    main()
