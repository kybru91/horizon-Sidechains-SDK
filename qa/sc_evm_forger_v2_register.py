#!/usr/bin/env python3
import logging
import time
from decimal import Decimal

from eth_utils import add_0x_prefix

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import generate_block_and_get_tx_receipt, contract_function_call, \
    ac_registerForger, ac_pagedForgersStakesByForger, ac_pagedForgersStakesByDelegator
from SidechainTestFramework.account.utils import convertZenToZennies, FORGER_STAKE_SMART_CONTRACT_ADDRESS, \
    VERSION_1_3_FORK_EPOCH, \
    VERSION_1_4_FORK_EPOCH, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS, convertZenniesToWei, convertZenToWei
from SidechainTestFramework.scutil import generate_next_block, EVM_APP_SLOT_TIME
from sc_evm_forger import print_current_epoch_and_slot
from test_framework.util import (
    assert_equal, assert_true, fail, forward_transfer_to_sidechain, )

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

        staked_amount = convertZenToZennies(10)
        # Create one more forger keys pair on node 1
        block_sign_pub_key_1_2 = sc_node_1.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key_1_2 = sc_node_1.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]
        self.sc_sync_all()

        # negative tests
        #==============================================================================================================
        # - try adding the same forger as the genesis one
        result = ac_registerForger(sc_node_1, block_sign_pub_key_genesis, vrf_pub_key_genesis, staked_amount, reward_share=0,
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
        result = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount - 1, reward_share=0,
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

        # register a new forger
        result = ac_registerForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2, staked_amount, reward_share=123,
                                   smart_contract_address=add_0x_prefix(evm_address_sc_node_2), nonce=None)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Registering a forger should succeed")

        # we have two forgers now, check legacy command
        stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(2, len(stake_list))

        # genesis forger
        list1 = ac_pagedForgersStakesByForger(sc_node_1, block_sign_pub_key_genesis, vrf_pub_key_genesis)
        assert_equal(list1['result']['stakes'][0]['stakedAmount'], convertZenToWei(self.forward_amount))
        assert_equal(list1['result']['stakes'][0]['delegator']['address'], delegator_address_genesis)

        # new forger
        list2 = ac_pagedForgersStakesByForger(sc_node_1, block_sign_pub_key_1_2, vrf_pub_key_1_2)
        assert_equal(list2['result']['stakes'][0]['stakedAmount'], convertZenniesToWei(staked_amount))

        # register a new forger at node2
        staked_amount2 = convertZenToZennies(33)

        result = ac_registerForger(sc_node_2, block_sign_pub_key_2, vrf_pub_key_2, staked_amount2, reward_share=123,
                                   smart_contract_address=add_0x_prefix(evm_address_sc_node_2), nonce=None)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        # Checking the receipt
        tx_id = result['result']['transactionId']
        receipt = sc_node_2.rpc_eth_getTransactionReceipt(add_0x_prefix(tx_id))
        status = int(receipt['result']['status'], 16)
        assert_equal(1, status, "Registering a forger should succeed")

        list3 = ac_pagedForgersStakesByForger(sc_node_2, block_sign_pub_key_2, vrf_pub_key_2)
        assert_equal(list3['result']['stakes'][0]['stakedAmount'], convertZenniesToWei(staked_amount2))

        list4 = ac_pagedForgersStakesByDelegator(sc_node_1, add_0x_prefix(evm_address_sc_node_1))
        assert_equal(list4['result']['stakes'][0]['stakedAmount'], convertZenniesToWei(staked_amount))
        assert_equal(list4['result']['stakes'][0]['forgerPublicKeys']['blockSignPublicKey']['publicKey'], block_sign_pub_key_1_2)
        assert_equal(list4['result']['stakes'][0]['forgerPublicKeys']['vrfPublicKey']['publicKey'], vrf_pub_key_1_2)

        list5 = ac_pagedForgersStakesByDelegator(sc_node_1, add_0x_prefix(delegator_address_genesis))
        assert_equal(list5['result']['stakes'][0]['stakedAmount'], convertZenToWei(self.forward_amount))
        assert_equal(list5['result']['stakes'][0]['forgerPublicKeys']['blockSignPublicKey']['publicKey'], block_sign_pub_key_genesis)
        assert_equal(list5['result']['stakes'][0]['forgerPublicKeys']['vrfPublicKey']['publicKey'], vrf_pub_key_genesis)

if __name__ == "__main__":
    SCEvmForgerV2register().main()
