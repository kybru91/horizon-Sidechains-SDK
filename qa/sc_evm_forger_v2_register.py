#!/usr/bin/env python3
import json
import logging
import time
from decimal import Decimal

from eth_abi import decode
from eth_utils import add_0x_prefix, encode_hex, event_signature_to_log_topic, remove_0x_prefix

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import format_eoa, ac_makeForgerStake, \
    generate_block_and_get_tx_receipt, contract_function_static_call, contract_function_call, estimate_gas, \
    ac_registerForger
from SidechainTestFramework.account.httpCalls.wallet.balance import http_wallet_balance
from SidechainTestFramework.account.simple_proxy_contract import SimpleProxyContract
from SidechainTestFramework.account.utils import convertZenToWei, \
    convertZenToZennies, computeForgedTxFee, convertWeiToZen, \
    FORGER_STAKE_SMART_CONTRACT_ADDRESS, WITHDRAWAL_REQ_SMART_CONTRACT_ADDRESS, VERSION_1_3_FORK_EPOCH, \
    VERSION_1_4_FORK_EPOCH
from SidechainTestFramework.scutil import generate_next_block, EVM_APP_SLOT_TIME
from sc_evm_forger import print_current_epoch_and_slot, decode_list_of_forger_stakes, \
    check_make_forger_stake_event, check_spend_forger_stake_event
from test_framework.util import (
    assert_equal, assert_true, fail, forward_transfer_to_sidechain, hex_str_to_bytes, bytes_to_hex_str, )

"""
If it is run with --allforks, all the existing forks are enabled at epoch 2, so it will use Shanghai EVM.
Configuration: 
    - 2 SC nodes connected with each other
    - 1 MC node
    - SC node 1 owns a stakeAmount made out of cross chain creation output

Test:
    - Create some stakes with different owners for node 1 forger before changing storage model 
    - Check that upgrade, stakeOf and getPagedForgersStakesByUser cannot be called before fork 1.3
    - Reach fork point 1.3. Check that stakeOf and getPagedStakesOfUser cannot be called before calling upgrade
    - Execute upgrade and verify that the stakes are the same as before
    - test getPagedStakesOfUser
    - test stakeOf
    - Execute some basic tests just to be sure everything works as before:
        - try spending a stake which does not own (exception expected)
        - Try to delegate stake to a native smart contract. It should fail
        - Try to delegate stake to a smart contract. It should fail.
    - SC1 Delegate 300 Zen and 200 Zen to SC2
    - Check that SC2 can not forge before two epochs are passed by, and afterwards it can
    - SC1 spends all its stake
    - SC1 can still forge blocks but after two epochs it can not anymore
    - Test the getPagedStakesOfUser and stakeOf can be called by an EVM Smart contract
    - removes all remaining stakes
    - Verify that it is not possible to forge new SC blocks from the next epoch switch on
    

"""

class SCEvmForgerV2register(AccountChainSetup):
    def __init__(self):
        super().__init__(number_of_sidechain_nodes=2, forward_amount=100,
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
        block_sign_pub_key_1 = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["blockSignPublicKey"][
            "publicKey"]
        vrf_pub_key_1 = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["vrfPublicKey"]["publicKey"]

        # Create forger keys on node 2
        block_sign_pub_key_2 = sc_node_2.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key_2 = sc_node_2.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]


        # Reach fork point 1.3
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_3_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

        native_contract = SmartContract("ForgerStakes")

        # Execute upgrade. First try just the static call, to verify that the method's result is correct.
        # Then actually execute the transaction

        method = 'upgrade()'
        res = contract_function_static_call(sc_node_1, native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                                            evm_address_sc_node_1, method)

        assert_equal(1, res[0], "Storage version should have been version 2")  # Version 2 has value 1

        # Execute upgrade
        tx_hash = contract_function_call(sc_node_1, native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_1, method)

        # Check the receipt
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')

        # Reach fork point 1.4
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_4_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

        staked_amount = convertZenToZennies(10)
        result = ac_registerForger(sc_node_1, block_sign_pub_key_1, vrf_pub_key_1, staked_amount, reward_share=123, smart_contract_address=None, nonce=None)

        self.sc_sync_all()

        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Registering a forger should succeed")

        # negative tests
        # - try adding the same forger
        result = ac_registerForger(sc_node_1, block_sign_pub_key_1, vrf_pub_key_1, staked_amount, reward_share=0, smart_contract_address=None, nonce=None)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()
        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(0, status, "adding an existing forger should result in a reverted tx")

        # - try staking an invalid amount (too low)
        block_sign_pub_key_1b = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["blockSignPublicKey"][
            "publicKey"]
        vrf_pub_key_1b = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["vrfPublicKey"]["publicKey"]

        result = ac_registerForger(sc_node_1, block_sign_pub_key_1b, vrf_pub_key_1b, staked_amount-1, reward_share=0, smart_contract_address=None, nonce=None)
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
        erroredRes = ac_registerForger(sc_node_1, block_sign_pub_key_2, vrf_pub_key_1, staked_amount, reward_share=0,
                                       smart_contract_address=None, nonce=None)
        if ('error' not in erroredRes):
            fail("Should not be able to create a valid signature 25519")
        else:
            assert_true("blockSignPubKey" in erroredRes['error']['detail'])

        #   . invalid vrf key (key not in wallet)
        erroredRes = ac_registerForger(sc_node_1, block_sign_pub_key_1, vrf_pub_key_2, staked_amount, reward_share=0,
                          smart_contract_address=None, nonce=None)
        if ('error' not in erroredRes):
            fail("Should not be able to create a valid vrf signature")
        else:
            assert_true("vrfPublicKey" in erroredRes['error']['detail'])

        #   . invalid reward share (not in allowed range)
        try:
            ac_registerForger(sc_node_1, block_sign_pub_key_1, vrf_pub_key_1, staked_amount, reward_share=1001,
                          smart_contract_address=None, nonce=None)
        except Exception as e:
            logging.info("We had an exception as expected: {}".format(str(e)))
            assert_true("Reward share" in str(e.error))
        else:
            fail("Should not be able to use an illegal reward share value")




if __name__ == "__main__":
    SCEvmForgerV2register().main()
