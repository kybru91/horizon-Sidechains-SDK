#!/usr/bin/env python3
import logging
import time
from decimal import Decimal

from eth_abi import decode
from eth_utils import add_0x_prefix, remove_0x_prefix, event_signature_to_log_topic, encode_hex

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import generate_block_and_get_tx_receipt, contract_function_call, \
    ac_registerForger, ac_pagedForgersStakesByForger, ac_pagedForgersStakesByDelegator, rpc_get_balance
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

        # Try registerForger before fork 1.4
        # Create one more forger keys pair on node 1
        block_sign_pub_key_1_2 = sc_node_1.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key_1_2 = sc_node_1.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]
        self.sc_sync_all()

        staked_amount = convertZenToZennies(10)
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_share=0,
                                smart_contract_address=None, nonce=None)
        assert_true('error' in res)
        assert_equal('0204', res['error']['code'])
        assert_true('Fork 1.4 is not active, can not invoke this command' in res['error']['description'])

        # Reach fork point 1.4
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_4_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

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
                                   reward_share=0,
                                   smart_contract_address=None, nonce=None)
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
                                   reward_share=0,
                                   smart_contract_address=None, nonce=None)
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
        errored_res = ac_registerForger(sc_node_1, block_sign_pub_key_2, vrf_pub_key_1_2, staked_amount, reward_share=0,
                                        smart_contract_address=None, nonce=None)
        if 'error' not in errored_res:
            fail("Should not be able to create a valid signature 25519")
        else:
            assert_true("blockSignPubKey" in errored_res['error']['detail'])

        #   . invalid vrf key (key not in wallet)
        errored_res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_2, staked_amount, reward_share=0,
                                        smart_contract_address=None, nonce=None)
        if 'error' not in errored_res:
            fail("Should not be able to create a valid vrf signature")
        else:
            assert_true("vrfPublicKey" in errored_res['error']['detail'])

        #   . invalid reward share (not in allowed range)
        try:
            ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_share=1001,
                              smart_contract_address=None, nonce=None)
        except Exception as e:
            logging.info("We had an exception as expected: {}".format(str(e)))
            assert_true("Reward share" in str(e.error))
        else:
            fail("Should not be able to use an illegal reward share value")

        #   . invalid reward share/reward address
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_share=1000,
                                smart_contract_address=None, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true(
            'Reward share cannot be different from 0 if reward address is not defined' in res['error']['description'])

        reward_address = add_0x_prefix(evm_address_sc_node_2)
        res = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_share=0,
                                smart_contract_address=reward_address, nonce=None)
        assert_true('error' in res)
        assert_equal('0211', res['error']['code'])
        assert_true('Reward share cannot be 0 if reward address is defined ' in res['error']['description'])

        # register a new forger
        evm_address_sc_node_1_balance = rpc_get_balance(sc_node_1, evm_address_sc_node_1)
        forger_contract_balance = rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)

        reward_share = 123
        result = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount,
                                   reward_share=reward_share,
                                   smart_contract_address=reward_address, nonce=None)
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
        assert_equal(list1['result']['stakes'][0]['stakedAmount'], convertZenToWei(self.forward_amount))
        assert_equal(list1['result']['stakes'][0]['delegator']['address'], delegator_address_genesis)

        # second forger
        evm_address_sc_node_2_balance = rpc_get_balance(sc_node_1, evm_address_sc_node_2)
        list2 = ac_pagedForgersStakesByForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2)
        assert_equal(list2['result']['stakes'][0]['stakedAmount'], staked_amount_in_wei)

        # register a third forger at node2 using native smart contract. This is for testing purposes, we are hard coding
        # the correct signatures corresponding to pub keys and message to sign
        register_forger_method = 'registerForger(bytes32,bytes32,bytes1,uint32,address,bytes32,bytes32,bytes32,bytes32,bytes32,bytes1)'
        staked_amount_2_in_wei = convertZenToWei(33)
        reward_share = 1000
        reward_address = evm_address_sc_node_2
        reward_address_bytes = hex_str_to_bytes(reward_address)

        forger_sign_key_bytes = hex_str_to_bytes(block_sign_pub_key_2)
        forger_vrf_key_bytes = hex_str_to_bytes(vrf_pub_key_2)
        signature25519_bytes = hex_str_to_bytes(
            "0c730e119711cef778ffb55d7dee9aefcd4d404c1387134d7cd5da28b0fa7a8ecce79eadea977c76d5f200016d90e46af1d5de343a072ae838d604965cc9460c")
        signature_vrf_bytes = hex_str_to_bytes(
            "8709b523d0f82ce70b4606ae1453fa8a1102b0fee503dc5f67ea4769ad1da61900d6c214d49b6cde58e0a20f21b03c9e31059681cf4446031cf3e5c0f6f5fb530d48b553506bbb3ab29e2b445d6aa22d3a06acb6322c3ad1e1e52faa9ab4196f3b")

        tx_id = contract_function_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                       evm_address_sc_node_1, register_forger_method,
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
        assert_equal(list3['result']['stakes'][0]['stakedAmount'], staked_amount_2_in_wei)

        list4 = ac_pagedForgersStakesByDelegator(sc_node_1, add_0x_prefix(evm_address_sc_node_1))
        assert_equal(list4['result']['stakes'][0]['stakedAmount'], staked_amount_in_wei)
        assert_equal(list4['result']['stakes'][0]['forgerPublicKeys']['blockSignPublicKey']['publicKey'],
                     block_sign_pub_key_1_2)
        assert_equal(list4['result']['stakes'][0]['forgerPublicKeys']['vrfPublicKey']['publicKey'], vrf_pub_key_1_2)

        list5 = ac_pagedForgersStakesByDelegator(sc_node_1, add_0x_prefix(delegator_address_genesis))
        assert_equal(list5['result']['stakes'][0]['stakedAmount'], convertZenToWei(self.forward_amount))
        assert_equal(list5['result']['stakes'][0]['forgerPublicKeys']['blockSignPublicKey']['publicKey'],
                     block_sign_pub_key_genesis)
        assert_equal(list5['result']['stakes'][0]['forgerPublicKeys']['vrfPublicKey']['publicKey'], vrf_pub_key_genesis)


def check_register_event(delegate_event, sender, vrf_pub_key, block_sign_pub_key, staked_amount, rewards_share,
                         reward_address):
    assert_equal(4, len(delegate_event['topics']), "Wrong number of topics in register_event")
    event_id = remove_0x_prefix(delegate_event['topics'][0])
    event_signature = remove_0x_prefix(
        encode_hex(
            event_signature_to_log_topic('RegisterForger(address,bytes32,bytes32,bytes1,uint256,uint32,address)')))
    assert_equal(event_signature, event_id, "Wrong event signature in topics")

    from_addr = decode(['address'], hex_str_to_bytes(delegate_event['topics'][1][2:]))[0][2:]
    assert_equal(sender.lower(), from_addr.lower(), "Wrong from address in topics")

    vrf1 = decode(['bytes32'], hex_str_to_bytes(delegate_event['topics'][2][2:]))[0]
    vrf2 = decode(['bytes1'], hex_str_to_bytes(delegate_event['topics'][3][2:]))[0]

    assert_equal(vrf_pub_key,
                 bytes_to_hex_str(vrf1) + bytes_to_hex_str(vrf2), "wrong vrfPublicKey")

    (sign_pub_key, value, share, reward_contract_address) = decode(['bytes32', 'uint256', 'uint32', 'address'],
                                                                   hex_str_to_bytes(delegate_event['data'][2:]))
    assert_equal(block_sign_pub_key, bytes_to_hex_str(sign_pub_key), "Wrong sign_pub_key in event")
    assert_equal(staked_amount, value, "Wrong amount in event")
    assert_equal(rewards_share, share, "Wrong rewards_share in event")
    assert_equal(reward_address, reward_address, "Wrong reward_address in event")


if __name__ == "__main__":
    SCEvmForgerV2register().main()
