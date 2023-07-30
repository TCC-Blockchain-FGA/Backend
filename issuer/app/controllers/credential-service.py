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

from agent import Steward, Issuer, Holder, Validator

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

async def pool_genesys(protocol_version, pool_name, pool_config):
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

    validator = Validator()
    await validator.create(pool_handle, json.dumps({"id": "validator_wallet"}), json.dumps({"key": "validator_wallet_key"}))

    await steward.simple_onboarding(validator.did, validator.verkey, validator.role)

    proof_req = validator.build_proof_request('gvt', '', '')

    proof_json, schemas_json, cred_defs_json = await prover.proof_req_to_get_cred(proof_req, schema_id, cred_def_id)
    assert await validator.validate_proof(proof_req, proof_json, schemas_json, cred_defs_json, '{}')

    await issuer.delete()
    await prover.delete()
    await validator.delete()

    try:
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
