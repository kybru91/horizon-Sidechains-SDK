#!/usr/bin/env python3
import time
import logging
from decimal import Decimal

from eth_abi import decode
from eth_utils import add_0x_prefix, remove_0x_prefix, event_signature_to_log_topic, encode_hex, to_checksum_address

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import generate_block_and_get_tx_receipt, contract_function_call, \
    ac_registerForger, ac_pagedForgersStakesByForger, ac_pagedForgersStakesByDelegator, rpc_get_balance, \
    ac_updateForger, format_evm
from SidechainTestFramework.account.utils import convertZenToZennies, FORGER_STAKE_SMART_CONTRACT_ADDRESS, \
    VERSION_1_3_FORK_EPOCH, \
    VERSION_1_4_FORK_EPOCH, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS, convertZenniesToWei, convertZenToWei, \
    computeForgedTxFee
from SidechainTestFramework.scutil import generate_next_block, EVM_APP_SLOT_TIME
from sc_evm_forger import print_current_epoch_and_slot
from test_framework.util import (
    assert_equal, assert_true, fail, forward_transfer_to_sidechain, hex_str_to_bytes, bytes_to_hex_str, )

"""
Configuration: 
    - 2 SC nodes connected with each other
    - 1 MC node
    - SC node 1 owns a stakeAmount made out of cross chain creation output

Test:
    - Reach fork point 1.3 and execute upgrade 
    - Reach fork point 1.4 and execute activate 
    - Try registering a forger with the same keys as the genesis one (fails)
    - Do some negative test with bad parameters
    - register a new forger on node1 and a new forger on node2
    - Test get all stakes and get paginate by forger methods
    

"""


class SCEvmForgerV2register(AccountChainSetup):
    def __init__(self):
        super().__init__(number_of_sidechain_nodes=2, forward_amount=222,
                         block_timestamp_rewind=1500 * EVM_APP_SLOT_TIME * VERSION_1_3_FORK_EPOCH)

    def run_test(self):
        if self.options.all_forks:
            logging.info("This test cannot be executed with --allforks")
            exit()

        mc_node = self.nodes[0]
        sc_node_1 = self.sc_nodes[0]
        sc_node_2 = self.sc_nodes[1]

        # transfer a small fund from MC to SC2 at a new evm address, do not mine mc block
        # this is for enabling SC 2 gas fee payment when sending txes
        evm_address_sc_node_2 = sc_node_2.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]

        ft_amount_in_zen_2 = Decimal('500.0')

        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      evm_address_sc_node_2,
                                      ft_amount_in_zen_2,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=False)

        time.sleep(2)  # MC needs this

        # transfer some fund from MC to SC1 at a new evm address, then mine mc block
        evm_address_sc_node_1 = sc_node_1.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]

        ft_amount_in_zen = Decimal('1000.0')

        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      evm_address_sc_node_1,
                                      ft_amount_in_zen,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=True)
        self.sync_all()

        # Generate SC block and check that FTs appears in SCs node wallet
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        print_current_epoch_and_slot(sc_node_1)

        # Get node 1 forger keys
        forger_stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        block_sign_pub_key_genesis = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["blockSignPublicKey"][
            "publicKey"]
        vrf_pub_key_genesis = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["vrfPublicKey"]["publicKey"]
        delegator_address_genesis = forger_stake_list[0]['forgerStakeData']["ownerPublicKey"]["address"]

        # Create forger keys on node 2
        block_sign_pub_key_2 = sc_node_2.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key_2 = sc_node_2.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]

        # Reach fork point 1.3
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_3_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

        native_contract = SmartContract("ForgerStakes")

        # Execute upgrade
        method = 'upgrade()'
        tx_hash = contract_function_call(sc_node_1, native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_1, method)

        # Check the receipt
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')

        # Create one more forger keys pair on node 1
        block_sign_pub_key_1_2 = sc_node_1.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key_1_2 = sc_node_1.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]
        self.sc_sync_all()

        MIN_STAKED_AMOUNT_IN_ZEN = 10
        staked_amount = convertZenToZennies(MIN_STAKED_AMOUNT_IN_ZEN)

        # Try registerForger before fork 1.4
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_address=None,
                                reward_share=0, nonce=None)
        assert_true('error' in res)
        assert_equal('0204', res['error']['code'])
        assert_true('Fork 1.4 is not active, can not invoke this command' in res['error']['description'])

        # Reach fork point 1.4
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_4_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

        # Try registerForger before storage activation
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_address=None,
                                reward_share=0, nonce=None)
        assert_true('error' in res)
        assert_equal('0204', res['error']['code'])
        assert_true('Forger Stake Storage V2 is not active' in res['error']['description'])

        # Execute activate.
        forger_v2_native_contract = SmartContract("ForgerStakesV2")
        method = 'activate()'
        tx_hash = contract_function_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_1, method)

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        self.sc_sync_all()

        # Check the receipt and the event log
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')
        intrinsic_gas = 21000 + 4 * 16  # activate signature are 4 non-zero bytes
        assert_equal(intrinsic_gas, int(tx_receipt['gasUsed'], 16), "wrong used gas")
        assert_equal(2, len(tx_receipt['logs']), 'Wrong number of logs')

        # negative tests
        # ==============================================================================================================
        # - try adding the same forger as the genesis one
        result = ac_registerForger(sc_node_1, block_sign_pub_key_genesis, vrf_pub_key_genesis, staked_amount,
                                   reward_address=None, reward_share=0, nonce=None)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(0, status, "adding an existing forger should result in a reverted tx")

        # - try staking an invalid amount (too low)
        result = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount - 1,
                                   reward_address=None, reward_share=0, nonce=None)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(0, status, "registering with an invalid stake amount should result in a reverted tx")

        # - try adding a forger with some illegal parameters
        #   . invalid signer key 25519 (key not in wallet)
        errored_res = ac_registerForger(sc_node_1, block_sign_pub_key_2, vrf_pub_key_1_2, staked_amount,
                                        reward_address=None, reward_share=0, nonce=None)
        if 'error' not in errored_res:
            fail("Should not be able to create a valid signature 25519")
        else:
            assert_true("blockSignPubKey" in errored_res['error']['detail'])

        #   . invalid vrf key (key not in wallet)
        errored_res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_2, staked_amount,
                                        reward_address=None, reward_share=0, nonce=None)
        if 'error' not in errored_res:
            fail("Should not be able to create a valid vrf signature")
        else:
            assert_true("vrfPublicKey" in errored_res['error']['detail'])

        #   . invalid reward share (not in allowed range)
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_address=None,
                                reward_share=1001, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true(
            'Reward share must be in the range [0, 1000]' in res['error']['description'])

        #   . invalid reward share/reward address
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_address=None,
                                reward_share=1000, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true(
            'Reward share cannot be different from 0 if reward address is null' in res['error']['description'])

        reward_address = add_0x_prefix(evm_address_sc_node_2)
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount,
                                reward_address=reward_address, reward_share=0, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true('Reward share cannot be 0 if reward address is defined ' in res['error']['description'])


        #   . invalid reward address string (wrong length)
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_address="0x111111112222222233333333444444445555555566",
                                reward_share=1000, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true(
            'Invalid address string length' in res['error']['description'])

        #   . invalid reward address string (wrong hex string)
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_address="0x111111112222222233333333444444445555555h",
                                reward_share=1000, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true(
            'Unrecognized character: h' in res['error']['description'])

        # register a new forger
        reward_share = 0
        evm_address_sc_node_1_balance = rpc_get_balance(sc_node_1, evm_address_sc_node_1)
        forger_contract_balance = rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

        result = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_share=reward_share)

        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Registering a forger should succeed")
        assert_equal(1, len(receipt['result']['logs']), 'Wrong number of logs')
        register_event = receipt['result']['logs'][0]
        staked_amount_in_wei = convertZenniesToWei(staked_amount)
        check_register_event(register_event, evm_address_sc_node_1, vrf_pub_key_1_2, block_sign_pub_key_1_2,
                             staked_amount_in_wei, reward_share, reward_address)

        gas_fee_paid, _, _ = computeForgedTxFee(sc_node_1, tx_id)
        assert_equal(evm_address_sc_node_1_balance - staked_amount_in_wei - gas_fee_paid,
                     rpc_get_balance(sc_node_1, evm_address_sc_node_1))
        assert_equal(staked_amount_in_wei + forger_contract_balance,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_contract_balance += staked_amount_in_wei

        # we have two forgers now, check legacy command
        stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(2, len(stake_list))

        # genesis forger
        list1 = ac_pagedForgersStakesByForger(sc_node_1, block_sign_pub_key_genesis, vrf_pub_key_genesis)
        assert_equal(1, len(list1))
        assert_equal(list1['result']['stakes'][0]['stakedAmount'], convertZenToWei(self.forward_amount))
        assert_equal(list1['result']['stakes'][0]['delegator']['address'], delegator_address_genesis)

        # second forger
        evm_address_sc_node_2_balance = rpc_get_balance(sc_node_1, evm_address_sc_node_2)
        list2 = ac_pagedForgersStakesByForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2)
        assert_equal(1, len(list2))
        assert_equal(list2['result']['stakes'][0]['stakedAmount'], staked_amount_in_wei)

        # register a third forger at node2 using native smart contract. This is for testing purposes, we are hard coding
        # the correct signatures corresponding to pub keys and message to sign
        reward_share = 1000
        reward_address = evm_address_sc_node_2
        reward_address_bytes = hex_str_to_bytes(reward_address)

        forger_sign_key_bytes = hex_str_to_bytes(block_sign_pub_key_2)
        forger_vrf_key_bytes = hex_str_to_bytes(vrf_pub_key_2)
        signature25519_bytes = hex_str_to_bytes(
            "776c7362afed8799826d1c61a202c248d11c82866c804db3ed919ecef8581fc65db2a019a543197fa150a3b923aca950b377cbd12701afe4c53361f29f971709")
        signature_vrf_bytes = hex_str_to_bytes(
            "d710141f62b7f656aaa21ae6fba716774d38e39708374c8b6e6a059482204e2a00e4dd3aabc76d76744e39f2f3e35c26c4ac7837d6ebc757ba4b31fbf92a1b9e0ea337dbf3deecb39e9df9134fc79107469d79acf44ee215eb7e063ab083489725")

        staked_amount_2_in_wei = convertZenToWei(33)
        register_forger_method = 'registerForger(bytes32,bytes32,bytes1,uint32,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes1)'
        tx_id = contract_function_call(sc_node_2, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                       evm_address_sc_node_2, register_forger_method,
                                       forger_sign_key_bytes,
                                       forger_vrf_key_bytes[0:32],
                                       forger_vrf_key_bytes[32:],
                                       reward_share,
                                       reward_address_bytes,
                                       signature25519_bytes[0:32],
                                       signature25519_bytes[32:],
                                       signature_vrf_bytes[0:32],
                                       signature_vrf_bytes[32:64],
                                       signature_vrf_bytes[64:96],
                                       signature_vrf_bytes[96:],
                                       value=staked_amount_2_in_wei)
        self.sc_sync_all()

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        self.sc_sync_all()

        # Checking the receipt
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Registering a forger should succeed")
        register_event = receipt['result']['logs'][0]
        check_register_event(register_event, evm_address_sc_node_2, vrf_pub_key_2, block_sign_pub_key_2,
                             staked_amount_2_in_wei, reward_share, reward_address)

        gas_fee_paid, _, _ = computeForgedTxFee(sc_node_2, tx_id)
        assert_equal(evm_address_sc_node_2_balance - staked_amount_2_in_wei - gas_fee_paid,
                     rpc_get_balance(sc_node_2, evm_address_sc_node_2))
        assert_equal(staked_amount_2_in_wei + forger_contract_balance,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_contract_balance += staked_amount_2_in_wei

        list3 = ac_pagedForgersStakesByForger(sc_node_2, block_sign_pub_key_2, vrf_pub_key_2)
        assert_equal(1, len(list3))
        assert_equal(list3['result']['stakes'][0]['stakedAmount'], staked_amount_2_in_wei)

        list4 = ac_pagedForgersStakesByDelegator(sc_node_1, add_0x_prefix(evm_address_sc_node_1))
        assert_equal(1, len(list4))
        assert_equal(list4['result']['stakes'][0]['stakedAmount'], staked_amount_in_wei)
        assert_equal(list4['result']['stakes'][0]['forgerPublicKeys']['blockSignPublicKey']['publicKey'],
                     block_sign_pub_key_1_2)
        assert_equal(list4['result']['stakes'][0]['forgerPublicKeys']['vrfPublicKey']['publicKey'], vrf_pub_key_1_2)

        list5 = ac_pagedForgersStakesByDelegator(sc_node_1, add_0x_prefix(delegator_address_genesis))
        assert_equal(1, len(list5))
        assert_equal(list5['result']['stakes'][0]['stakedAmount'], convertZenToWei(self.forward_amount))
        assert_equal(list5['result']['stakes'][0]['forgerPublicKeys']['blockSignPublicKey']['publicKey'],
                     block_sign_pub_key_genesis)
        assert_equal(list5['result']['stakes'][0]['forgerPublicKeys']['vrfPublicKey']['publicKey'], vrf_pub_key_genesis)


        reward_share_updated = 1
        reward_address_updated = "0x1111111122222222333333334444444455555555"

        # negative tests
        # ==============================================================================================================
        # - try updating a forger that does not exist
        result = ac_updateForger(sc_node_1, block_sign_pub_key_genesis, vrf_pub_key_1_2,
                                 reward_address=reward_address_updated, reward_share=reward_share_updated)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(0, status, "Upgrade forger should fail")


        # - try updating a forger that currently has a reward share not null
        result = ac_updateForger(sc_node_2, block_sign_pub_key_2, vrf_pub_key_2,
                                 reward_address=reward_address_updated, reward_share=reward_share_updated)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(0, status, "Upgrade forger should fail")

        # - try updating a forger specifying a null reward_share
        res = ac_updateForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2,
                                 reward_address=reward_address_updated, reward_share=0)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true('Reward share must be in the range (0, 1000]' in res['error']['description'])

        # - try updating a forger with the null reward address
        res = ac_updateForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2,
                                 reward_address="0x0000000000000000000000000000000000000000", reward_share=reward_share_updated)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true('Reward address can not be the null address' in res['error']['description'])


        # - try updating a forger with an invalid reward address (wrong length)
        res = ac_updateForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2,
                                 reward_address="0x0", reward_share=reward_share_updated)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true('Invalid address string length' in res['error']['description'])

        # - try updating a forger with an invalid reward address (wrong hex string)
        res = ac_updateForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2,
                                 reward_address="0h11111111222222223333333344444444555555", reward_share=reward_share_updated)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true(
            'Unrecognized character: h' in res['error']['description'])

        # update first forger
        result = ac_updateForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2,
                                 reward_address=reward_address_updated, reward_share=reward_share_updated)

        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Upgrade a forger should succeed")
        assert_equal(1, len(receipt['result']['logs']), 'Wrong number of logs')
        update_event = receipt['result']['logs'][0]
        check_update_event(update_event, evm_address_sc_node_1, vrf_pub_key_1_2, block_sign_pub_key_1_2,
                           reward_share_updated, reward_address_updated)

        # Check getForger
        method = 'getForger(bytes32,bytes32,bytes1)'
        forger_sign_key_to_bytes = hex_str_to_bytes(block_sign_pub_key_1_2)
        forger_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_1_2)
        forger_keys_to_bytes = (forger_sign_key_to_bytes, forger_vrf_pub_key_to_bytes[:32],
                                  forger_vrf_pub_key_to_bytes[32:])
        data = forger_v2_native_contract.raw_encode_call(method, *forger_keys_to_bytes)

        result = sc_node_1.rpc_eth_call(
            {
                "to": format_evm(FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS),
                "from": format_evm(evm_address_sc_node_1),
                "input": data
            }, "latest"
        )

        forger_info = decode_forger_info(hex_str_to_bytes(result['result'][2:]))
        assert_equal(reward_share_updated, forger_info[2])
        assert_equal(add_0x_prefix(reward_address_updated), forger_info[3])

        # update genesis forger via contract call
        reward_share_gen_updated = 33
        reward_address_gen_updated = "3333333333333333333333333333333333333333"

        reward_address_bytes = hex_str_to_bytes(reward_address_gen_updated)
        forger_sign_key_bytes = hex_str_to_bytes(block_sign_pub_key_genesis)
        forger_vrf_key_bytes = hex_str_to_bytes(vrf_pub_key_genesis)
        signature25519_bytes = hex_str_to_bytes("e50f654c4bff1e99c282b0eec21ced63fac7ed28d9a7d4f6529c2dd7a7bce93fd419f1288c8c865a325f9b2a4439aab696384159b736f5ae1562e72f0638a50e")
        signature_vrf_bytes = hex_str_to_bytes("8f0964a947fe634832cfbef589ed5956792085cd462b5a44d64bd0d0bdc75a0c0062b9c5cc55680ebdec91917721668d725c3b5f4f5c8529f8ed4458c86fb831279e7c8abfefc30eca46c565928d9c89adf27e2359f3827fcc8b6f62f4a4b8ee36")

        update_forger_method = 'updateForger(bytes32,bytes32,bytes1,uint32,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes1)'
        tx_id = contract_function_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                       evm_address_sc_node_1, update_forger_method,
                                       forger_sign_key_bytes,
                                       forger_vrf_key_bytes[0:32],
                                       forger_vrf_key_bytes[32:],
                                       reward_share_gen_updated,
                                       reward_address_bytes,
                                       signature25519_bytes[0:32],
                                       signature25519_bytes[32:],
                                       signature_vrf_bytes[0:32],
                                       signature_vrf_bytes[32:64],
                                       signature_vrf_bytes[64:96],
                                       signature_vrf_bytes[96:])
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        self.sc_sync_all()

        # Checking the receipt
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Registering a forger should succeed")
        update_event = receipt['result']['logs'][0]
        check_update_event(update_event, evm_address_sc_node_1, vrf_pub_key_genesis, block_sign_pub_key_genesis,
                             reward_share_gen_updated, reward_address_gen_updated)


        # Check getForger
        method = 'getForger(bytes32,bytes32,bytes1)'
        forger_sign_key_to_bytes = hex_str_to_bytes(block_sign_pub_key_genesis)
        forger_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_genesis)
        forger_keys_to_bytes = (forger_sign_key_to_bytes, forger_vrf_pub_key_to_bytes[:32],
                                  forger_vrf_pub_key_to_bytes[32:])
        data = forger_v2_native_contract.raw_encode_call(method, *forger_keys_to_bytes)

        result = sc_node_1.rpc_eth_call(
            {
                "to": format_evm(FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS),
                "from": format_evm(evm_address_sc_node_1),
                "input": data
            }, "latest"
        )

        forger_info = decode_forger_info(hex_str_to_bytes(result['result'][2:]))
        assert_equal(reward_share_gen_updated, forger_info[2])
        assert_equal(add_0x_prefix(reward_address_gen_updated), forger_info[3])




def decode_forger_info(result):
    raw_stake = decode(['(bytes32,bytes32,bytes1,uint32,address)'], result)[0]
    forger_info = (bytes_to_hex_str(raw_stake[0]),
                   bytes_to_hex_str(raw_stake[1]) + bytes_to_hex_str(raw_stake[2]),
                   raw_stake[3], raw_stake[4])

    return forger_info

def check_register_event(register_forger_event, sender, vrf_pub_key, block_sign_pub_key, staked_amount, rewards_share,
                         reward_address):
    assert_equal(4, len(register_forger_event['topics']), "Wrong number of topics in register_event")
    event_id = remove_0x_prefix(register_forger_event['topics'][0])
    event_signature = remove_0x_prefix(
        encode_hex(
            event_signature_to_log_topic('RegisterForger(address,bytes32,bytes32,bytes1,uint256,uint32,address)')))
    assert_equal(event_signature, event_id, "Wrong event signature in topics")

    pubKey25519 = decode(['bytes32'], hex_str_to_bytes(register_forger_event['topics'][1][2:]))[0]
    assert_equal(block_sign_pub_key, bytes_to_hex_str(pubKey25519), "Wrong from address in topics")

    vrf1 = decode(['bytes32'], hex_str_to_bytes(register_forger_event['topics'][2][2:]))[0]
    vrf2 = decode(['bytes1'], hex_str_to_bytes(register_forger_event['topics'][3][2:]))[0]
    assert_equal(vrf_pub_key,
                 bytes_to_hex_str(vrf1) + bytes_to_hex_str(vrf2), "wrong vrfPublicKey")

    (from_addr, value, share, reward_contract_address) = decode(['address', 'uint256', 'uint32', 'address'],
                                                                hex_str_to_bytes(register_forger_event['data'][2:]))
    assert_equal(to_checksum_address(sender), to_checksum_address(from_addr), "Wrong sender in event")
    assert_equal(staked_amount, value, "Wrong amount in event")
    assert_equal(rewards_share, share, "Wrong rewards_share in event")
    assert_equal(reward_address, reward_address, "Wrong reward_address in event")


def check_update_event(update_forger_event, sender, vrf_pub_key, block_sign_pub_key, rewards_share,
                       reward_address):
    assert_equal(4, len(update_forger_event['topics']), "Wrong number of topics in update forger event")
    event_id = remove_0x_prefix(update_forger_event['topics'][0])
    event_signature = remove_0x_prefix(
        encode_hex(
            event_signature_to_log_topic('UpdateForger(address,bytes32,bytes32,bytes1,uint32,address)')))
    assert_equal(event_signature, event_id, "Wrong event signature in topics")

    from_addr = decode(['address'], hex_str_to_bytes(update_forger_event['topics'][1][2:]))[0][2:]
    assert_equal(sender.lower(), from_addr.lower(), "Wrong from address in topics")

    vrf1 = decode(['bytes32'], hex_str_to_bytes(update_forger_event['topics'][2][2:]))[0]
    vrf2 = decode(['bytes1'], hex_str_to_bytes(update_forger_event['topics'][3][2:]))[0]
    assert_equal(vrf_pub_key,
                 bytes_to_hex_str(vrf1) + bytes_to_hex_str(vrf2), "wrong vrfPublicKey")

    (pubKey25519, share, reward_contract_address) = decode(['bytes32', 'uint32', 'address'],
                                                         hex_str_to_bytes(update_forger_event['data'][2:]))

    assert_equal(block_sign_pub_key, bytes_to_hex_str(pubKey25519), "Wrong from address in topics")
    assert_equal(rewards_share, share, "Wrong rewards_share in event")
    assert_equal(reward_address, reward_address, "Wrong reward_address in event")


if __name__ == "__main__":
    SCEvmForgerV2register().main()
