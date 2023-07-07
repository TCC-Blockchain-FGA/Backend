from indy import pool, ledger, wallet, did, anoncreds, crypto
from indy.error import IndyError, ErrorCode
from typing import Optional
import json
import uuid
from enum import Enum
import pprint
import asyncio
import requests

class Roles(Enum):
    USER = None
    TRUSTEE = 0
    TRUST_ANCHOR = 0
    STEWARD = 2
    ENDORSER = 101
    NETWORK_MONITOR = 201


class Agent:
    def __init__(self) -> None:
        pass

    async def createAgent(self, pool_handle):
        self.pool = pool_handle
        self.wallet_config, self.wallet_credentials = self.create_wallet()
        self.wallet = await self.new_wallet(self.wallet_config, self.wallet_credentials)
        

    async def new_wallet(self, wallet_config, wallet_credentials):
        try:
            self.print_log('\n3. Creating new issuer, steward, and prover secure wallet\n')
            await wallet.create_wallet(wallet_config, wallet_credentials)
        except IndyError as e:
            if e.error_code == ErrorCode.WalletAlreadyExistsError:
                print('Wallet already exists!')
            else:
                print('Error occurred: %s' % e)
        wallet_handle = await self.open_wallet()
        return wallet_handle

    def print_log(self, value_color="", value_noncolor=""):
        """set the colors for text."""
        HEADER = '\033[92m'
        ENDC = '\033[0m'
        print(HEADER + value_color + ENDC + str(value_noncolor))

    async def generate_did(self, did_json):
        try:
            _did, _verkey = await did.create_and_store_my_did(self.wallet, did_json)
        except IndyError as e:
            print('Error occurred: %s' % e)
        return _did, _verkey
    
    def create_wallet():
        wallet_config = json.dumps({"id": f'{uuid.uuid4()}'})
        wallet_credentials = json.dumps({"key": f'wallet_key_{uuid.uuid4()}'})
        return [wallet_config, wallet_credentials]

    async def open_wallet(self):
        try:
            self.print_log('\n4. Open wallet and get handle from libindy\n')
            wallet_handle = await wallet.open_wallet(self.wallet_config, self.wallet_credentials)
        except IndyError as e:
            print('Error occurred: %s' % e)
            wallet_handle = -1
        return wallet_handle

    async def close_wallet(self):
        try:
            # 18.
            self.print_log('\n18. Closing both wallet_handles and pool\n')
            await wallet.close_wallet(self.wallet)
            self.wallet = 0
        except IndyError as e:
                print('Error occurred: %s' % e)

    async def connect_did(self, connection_request):
        ##recv this request

        self.print_log('\n Get key for did from other Peer connection request\n')

        to_verkey = await did.key_for_did(self.pool, self.wallet, connection_request['did'])

        self.print_log('\n Anoncrypt connection response for Holder with Peer DID, verkey and nonce\n')
                    
        connection_response = json.dumps({
            'did': self.did,
            'verkey': self.verkey,
            'nonce': connection_request['nonce']
        })

        ##send this response 
        await self.send_message_ab(connection_response.encode('utf-8'), to_verkey)

    async def send_message_ab(self, message, to_verkey):
        crypted_message = await crypto.pack_message(self.wallet, message, [to_verkey], self.verkey)
        return crypted_message
    async def recv_message_ba(self, crypted_message):
        """
        (Authcrypt mode)

        {
            "message": <decrypted message>,
            "recipient_verkey": <recipient verkey used to decrypt>,
            "sender_verkey": <sender verkey used to encrypt>
        }

        """
        message = await crypto.unpack_message(self.wallet, crypted_message)
        return message
    
    async def delete(self):
        try:
            # 18.
            self.print_log('\n18. Closing both wallet_handles and pool\n')
            await wallet.close_wallet(self.wallet)
        except IndyError as e:
                print('Error occurred: %s' % e)
        try:
            # 19.
            self.print_log('\n19. Deleting created wallet_handles\n')
            await wallet.delete_wallet(self.wallet_config, self.wallet_credentials)
        except IndyError as e:
                print('Error occurred: %s' % e)



class Steward(Agent):
    def __init__(self) -> None:
        super().__init__()
        pass
    async def create(self, pool_handle):
        await self.createAgent(pool_handle)
        self.role = 'STEWARD'
        self.print_log('\n5. Generating and storing steward DID and verkey\n')
        steward_seed = '000000000000000000000000Steward1'
        did_json = json.dumps({'seed': steward_seed})
        self.did , self.verkey = await self.generate_did(did_json)
        self.print_log('Steward DID: ', self.did)
        self.print_log('Steward Verkey: ', self.verkey)
        
    
    async def simple_onboarding(self, trust_anchor_did, trust_anchor_verkey, role):
        try:
            # 7.
            self.print_log('\n7. Building NYM request to add Trust Anchor to the ledger\n')
            nym_transaction_request = await ledger.build_nym_request(submitter_did=self.did,
                                                                    target_did=trust_anchor_did,
                                                                    ver_key=trust_anchor_verkey,
                                                                    alias=None,
                                                                    role=role)
            self.print_log('NYM transaction request: ')
            pprint.pprint(json.loads(nym_transaction_request))
        except IndyError as e:
                print('Error occurred: %s' % e)
        try:
            # 8.
            self.print_log('\n8. Sending NYM request to the ledger\n')
            nym_transaction_response = await ledger.sign_and_submit_request(pool_handle=self.pool,
                                                                            wallet_handle=self.wallet,
                                                                            submitter_did=self.did,
                                                                            request_json=nym_transaction_request)
            self.print_log('NYM transaction response: ')
            pprint.pprint(json.loads(nym_transaction_response))
        except IndyError as e:
                print('Error occurred: %s' % e)

    async def new_schema(self, schema_name, schema_atributes):
        try:
            # 9.
            (schema_id, schema) = \
            await anoncreds.issuer_create_schema(self.did, schema_name, '1.0',
                                              json.dumps(schema_atributes))
 
            self.print_log('Schema: ')
            pprint.pprint(schema)
            schema_request = await ledger.build_schema_request(self.did, schema)
            self.print_log('Schema request: ')
            pprint.pprint(json.loads(schema_request))
        except IndyError as e:
                print('Error occurred: %s' % e)
        try:
            # 10.
            self.print_log('\n10. Sending the SCHEMA request to the ledger\n')
            schema_response = await ledger.sign_and_submit_request(self.pool, self.wallet, self.did, schema_request)
            self.print_log('Schema response:')
            pprint.pprint(json.loads(schema_response))
        except IndyError as e:
            print('Error occurred: %s' % e)
        return schema_id                

class Issuer(Agent):
    def __init__(self) -> None:
        super().__init__()
        pass

    async def create(self, pool_handle):
        await self.createAgent(pool_handle)
        self.role = 'TRUST_ANCHOR'
        self.print_log(
            '\n6. Generating and storing trust anchor (also issuer) DID and verkey\n')
        (self.did, self.verkey) = await self.generate_did("{}")
        self.print_log('Trust anchor DID: ', self.did)
        self.print_log('Trust anchor Verkey: ', self.verkey)
    
    async def get_schema(self, schema_id):
        try:
            get_schema_request = await ledger.build_get_schema_request(self.did, schema_id)
            get_schema_response = await ledger.submit_request(self.pool, get_schema_request)
            (_, schema_json) = await ledger.parse_get_schema_response(get_schema_response)
        except IndyError as e:
                print('Error occurred: %s' % e)
        return schema_json
    
    async def new_cred_def(self, schema_id):
        try:
            # 11.
            schema_json = await self.get_schema(schema_id)
            self.print_log(
                '\n11. Creating and storing CRED DEFINITION using anoncreds as Trust Anchor, for the given Schema\n')
            cred_def_tag = 'cred_def_tag'
            cred_def_type = 'CL'
            cred_def_config = json.dumps({"support_revocation": False})

            (cred_def_id, cred_def_json) = \
            await anoncreds.issuer_create_and_store_credential_def(self.wallet, self.did, \
                     schema_json, cred_def_tag, cred_def_type, cred_def_config)
            cred_def_request = await ledger.build_cred_def_request(self.did, cred_def_json)
            await ledger.sign_and_submit_request(self.pool, self.wallet, self.did, cred_def_request)
            self.print_log('Credential definition: ')
            pprint.pprint(json.loads(cred_def_json))
        except IndyError as e:
                print('Error occurred: %s' % e)
        return cred_def_id

    async def new_cred_offer(self, cred_def_id):
        try:
            # 14.
            self.print_log(
                '\n14. Issuer (Trust Anchor) is creating a Credential Offer for Prover\n')
            cred_offer_json = await anoncreds.issuer_create_credential_offer(self.wallet, cred_def_id)
            self.print_log('Credential Offer: ')
            pprint.pprint(json.loads(cred_offer_json))
        except IndyError as e:
            print('Error occurred: %s' % e)
            cred_offer_json = '{}'
        return cred_offer_json

    async def request_to_cred_issue(self, cred_offer_json, cred_req_json, cred_values_json):
        try:
            # 16.
            self.print_log(
                '\n16. Issuer (Trust Anchor) creates Credential for Credential Request\n')
            (cred_json, _, _) = await anoncreds.issuer_create_credential(self.wallet, cred_offer_json, cred_req_json, cred_values_json, None, None)
            self.print_log('Credential: ')
            pprint.pprint(json.loads(cred_json))
        except IndyError as e:
            cred_json = '{}'
            print('Error occurred: %s' % e)
        return cred_json
    
    #Holder/Prover
class Holder(Agent):
    def __init__(self) -> None:
        super().__init__()
        pass

    async def create(self, pool_handle):
        await self.createAgent(pool_handle)
        self.did, self.verkey = await self.generate_did("{}")
        self.role = None
        try:
            # 13.
            self.print_log('\n13. Prover is creating Master Secret\n')
            master_secret_name = 'master_secret'
            self.master_secret_id = await anoncreds.prover_create_master_secret(self.wallet, master_secret_name)
        except IndyError as e:
            print('Error occurred: %s' % e)
        
    async def get_cred_def(self, cred_def_id):
        try:
            get_cred_def_request = await ledger.build_get_cred_def_request(self.did, cred_def_id)
            get_cred_def_response = await ledger.submit_request(self.pool, get_cred_def_request)
            (_, cred_def_json) = await ledger.parse_get_cred_def_response(get_cred_def_response)
        except IndyError as e:
            print('Error occurred: %s' % e)
            
        return cred_def_json

    async def offer_to_cred_request(self, cred_offer_json, cred_def_id):
        try:
            # 15.
            self.print_log(
                '\n15. Prover creates Credential Request for the given credential offer\n')
            cred_def_json = await self.get_cred_def(cred_def_id)

            (cred_req_json, cred_req_metadata_json) = await anoncreds.prover_create_credential_req(self.wallet, self.did, cred_offer_json, cred_def_json, self.master_secret_id)
            self.print_log('Credential Request: ')
            pprint.pprint(json.loads(cred_req_json))
        except IndyError as e:
            print('Error occurred: %s' % e)
        return (cred_req_json, cred_req_metadata_json)
    
    async def store_ver_cred(self, cred_req_metadata_json, cred_json, cred_def_id):
        try:
            cred_def_json = await self.get_cred_def(cred_def_id)
            # 17.
            self.print_log('\n17. Prover processes and stores Credential\n')
            await anoncreds.prover_store_credential(self.wallet, None, cred_req_metadata_json, cred_json, cred_def_json, None)

        except IndyError as e:
            print('Error occurred: %s' % e)
    
    async def proof_req_to_get_cred(self, proof_req_json, schema_id, cred_def_id):
        claims_for_proof_request_json = await anoncreds.prover_get_credentials_for_proof_req(self.wallet, proof_req_json)
        claims_for_proof_request = json.loads(claims_for_proof_request_json)
        self.print_log('Claims for Proof Request: ')
        pprint.pprint(claims_for_proof_request)
        # 19.
        self.print_log('\n19. Prover creates Proof for Proof Request\n')
        referent = claims_for_proof_request['attrs']['attr1_referent'][0]['cred_info']['referent']
        self.print_log('Referent: ')
        pprint.pprint(referent)
        requested_credentials_json = json.dumps({
            'self_attested_attributes': {},
            'requested_attributes': {
                'attr1_referent': {'cred_id': referent, 'revealed': True}
            },
            'requested_predicates': {},
        })
        pprint.pprint(json.loads(requested_credentials_json))
    
        schemas_json = {}
        get_schema_request = await ledger.build_get_schema_request(self.did, schema_id)
        get_schema_response = await ledger.submit_request(self.pool, get_schema_request)
        (received_schema_id, received_schema) = await ledger.parse_get_schema_response(get_schema_response)
        schemas_json[received_schema_id] = json.loads(received_schema)

        cred_defs_json = {}
        get_cred_def_request = await ledger.build_get_cred_def_request(self.did, cred_def_id)
        get_cred_def_response = await ledger.submit_request(self.pool, get_cred_def_request)
        (received_cred_def_id, received_cred_def) = await ledger.parse_get_cred_def_response(get_cred_def_response)
        cred_defs_json[received_cred_def_id] = json.loads(received_cred_def)
        
        revoc_regs_json = json.dumps({})

        proof_json = await anoncreds.prover_create_proof(self.wallet, proof_req_json, requested_credentials_json, self.master_secret_id, json.dumps(schemas_json), json.dumps(cred_defs_json), revoc_regs_json)
        
        return proof_json, schemas_json, cred_defs_json
        
        #assert 'Alex' == proof['requested_proof']['revealed_attrs']['attr1_referent'][1]


class Validator(Agent):
    def __init__(self) -> None:
        super().__init__()
        pass


    async def create(self, pool_handle):
        try:
            await self.createAgent(pool_handle)
            self.did, self.verkey = await self.generate_did("{}")
            self.role = 'ENDORSER'

        except IndyError as e:
            print('Error occurred: %s' % e)

    def build_proof_request(self, name, attrs, preds):
        nonce = str(123432421212)

        proof_request = {
            'nonce': nonce,
            'name': name,
            'version': '0.1',
            'requested_attributes': {
                'attr1_referent': {
                    'name': 'name'
                }
            },
        }
        self.print_log('Proof Request: ')
        pprint.pprint(proof_request)
        return json.dumps(proof_request)

    async def validate_proof(self, proof_req_json, proof_json, schemas_json, cred_defs_json, revoc_regs_json):
        #assert 'Alex' == proof['requested_proof']['revealed_attrs']['attr1_referent'][1]

        # 20.
        self.print_log('\n20.Verifier is verifying proof from Prover\n')
        return await anoncreds.verifier_verify_proof(proof_req_json, proof_json, json.dumps(schemas_json), json.dumps(cred_defs_json), revoc_regs_json, "{}")
