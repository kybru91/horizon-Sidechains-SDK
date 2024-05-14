#!/usr/bin/env python3
import json
import logging
import time
from decimal import Decimal

from eth_abi import decode
from eth_utils import encode_hex, event_signature_to_log_topic, remove_0x_prefix, add_0x_prefix

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import (ac_makeForgerStake, \
                                                     format_evm,
                                                     generate_block_and_get_tx_receipt, contract_function_static_call,
                                                     contract_function_call, format_eoa, \
                                                     rpc_get_balance)
from SidechainTestFramework.account.httpCalls.transaction.createEIP1559Transaction import createEIP1559Transaction
from SidechainTestFramework.account.simple_proxy_contract import SimpleProxyContract
from SidechainTestFramework.account.utils import convertZenToZennies, FORGER_STAKE_SMART_CONTRACT_ADDRESS, \
    VERSION_1_3_FORK_EPOCH, \
    VERSION_1_4_FORK_EPOCH, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS, convertZenToWei, computeForgedTxFee, \
    FORGER_POOL_RECIPIENT_ADDRESS
from SidechainTestFramework.scutil import generate_next_block, EVM_APP_SLOT_TIME
from httpCalls.block.getFeePayments import http_block_getFeePayments
from sc_evm_forger import print_current_epoch_and_slot
from test_framework.util import (
    assert_equal, assert_true, assert_false, fail, forward_transfer_to_sidechain, bytes_to_hex_str, hex_str_to_bytes, )

NULL_ADDRESS = '0x0000000000000000000000000000000000000000'

"""
If it is run with --allforks, all the existing forks are enabled at epoch 2, so it will use Shanghai EVM.
Configuration: 
    - 2 SC nodes connected with each other
    - 1 MC node
    - SC node 1 owns a stakeAmount made out of cross chain creation output

Test:
    - Activate Fork 1.3 and execute upgrade, in order to use storage model v2
    - Create some stakes with different owners for node 1 forger using the old native smart contract
    - Check that activate cannot be called on ForgerStake smart contract V2 before fork 1.4
    - Reach fork point 1.4. 
    - Try to execute disable on old Forger stake native contract and verify that it is not possible.
    - Try executing methods of ForgerStake smart contract V2 before calling activate and verify that it is not possible.
    - Execute activate on ForgerStake smart contract V2 and verify that the total amount of stakes are the same as before
    - Try methods of the old Forger stake native contract and verify they cannot be executed anymore
    - Try delegate and withdraw and verify they work as expected
    - Try executing methods of ForgerStake smart contract V2 from a smart contract and verify they work as expected

    

"""


class SCEvmNativeForgerV2(AccountChainSetup):
    def __init__(self):
        super().__init__(number_of_sidechain_nodes=2, forward_amount=100, withdrawalEpochLength=20,
                         block_timestamp_rewind=1500 * EVM_APP_SLOT_TIME * VERSION_1_4_FORK_EPOCH)

    def run_test(self):

        mc_node = self.nodes[0]
        sc_node_1 = self.sc_nodes[0]
        sc_node_2 = self.sc_nodes[1]

        # transfer a small fund from MC to SC2 at a new evm address, do not mine mc block
        # this is for enabling SC 2 gas fee payment when sending txes
        evm_address_sc_node_2 = sc_node_2.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]
        evm_address_sc_node_3 = sc_node_2.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]

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

        # Create some additional addresses, don't care the node
        evm_address_3 = sc_node_1.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]
        evm_address_4 = sc_node_2.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]
        evm_address_5 = sc_node_1.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]

        """Create some stakes for node 1 forger:
            - 1 with evm_address_sc_node_1 as owner
            - 3 with evm_address_sc_node_2 as owner
            - 2 with evm_address_3 as owner
            - 1 with evm_address_4 as owner
            - 1 with evm_address_5 as owner
        """
        ac_makeForgerStake(sc_node_1, evm_address_sc_node_1, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(2), 0)
        ac_makeForgerStake(sc_node_1, evm_address_sc_node_2, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(1), 1)
        ac_makeForgerStake(sc_node_1, evm_address_sc_node_2, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(11), 2)
        ac_makeForgerStake(sc_node_1, evm_address_3, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(2), 3)
        ac_makeForgerStake(sc_node_1, evm_address_sc_node_2, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(1), 4)
        ac_makeForgerStake(sc_node_1, evm_address_4, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(3), 5)
        ac_makeForgerStake(sc_node_1, evm_address_3, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(3), 6)
        ac_makeForgerStake(sc_node_1, evm_address_5, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(1), 7)
        self.sc_sync_all()

        # Generate SC block on SC node (keep epoch)
        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        self.sc_sync_all()

        orig_stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(9, len(orig_stake_list))

        exp_stake_own_1 = 0
        exp_stake_own_2 = 0
        exp_stake_own_3 = 0
        exp_stake_own_4 = 0
        exp_stake_own_5 = 0
        genesis_stake = 0
        for stake in orig_stake_list:
            if stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_1:
                exp_stake_own_1 += stake['forgerStakeData']['stakedAmount']
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_2:
                exp_stake_own_2 += stake['forgerStakeData']['stakedAmount']
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_3:
                exp_stake_own_3 += stake['forgerStakeData']['stakedAmount']
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_4:
                exp_stake_own_4 += stake['forgerStakeData']['stakedAmount']
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_5:
                exp_stake_own_5 += stake['forgerStakeData']['stakedAmount']
            else:
                genesis_stake += stake['forgerStakeData']['stakedAmount']

        # Reach fork point 1.3
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_3_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

        old_forger_native_contract = SmartContract("ForgerStakes")
        method = 'upgrade()'
        # Execute upgrade
        contract_function_call(sc_node_1, old_forger_native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                               evm_address_sc_node_1, method)

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
        self.sc_sync_all()

        forger_stake_balance = rpc_get_balance(sc_node_1, FORGER_STAKE_SMART_CONTRACT_ADDRESS)

        # Check that disable on old smart contract cannot be called before fork 1.4
        method = 'disableAndMigrate()'
        try:
            contract_function_static_call(sc_node_1, old_forger_native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method)
            fail("disableAndMigrate call should fail before fork point")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("op code not supported" in str(err))

        # Check that if activate is called before fork 1.4 it doesn't fail, but it is not executed. It is interpreted
        # as an EOA-to-EOA with a data not null.

        forger_v2_native_contract = SmartContract("ForgerStakesV2")
        method = 'activate()'
        tx_hash = contract_function_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_1, method, value=convertZenToZennies(2))

        self.sc_sync_all()
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')

        # Reach fork point 1.4
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        for i in range(0, VERSION_1_4_FORK_EPOCH - current_best_epoch):
            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()

        # Check that disable on old smart contract cannot be called from an account that is not
        # FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS
        method = 'disableAndMigrate()'
        try:
            contract_function_static_call(sc_node_1, old_forger_native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method)
            fail("disableAndMigrate call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Authorization failed" in str(err))

        # Check that delegate cannot be called before activate
        delegate_method = 'delegate(bytes32,bytes32,bytes1)'
        forger_1_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_1)
        forger_1_sign_key_to_bytes = hex_str_to_bytes(block_sign_pub_key_1)

        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, delegate_method,
                                          forger_1_sign_key_to_bytes, forger_1_vrf_pub_key_to_bytes[0:32],
                                          forger_1_vrf_pub_key_to_bytes[32:])
            fail("delegate call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger stake V2 has not been activated yet" in str(err))

        # Check that withdraw cannot be called before activate
        method = 'withdraw(bytes32,bytes32,bytes1,uint256)'
        forger_1_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_1)

        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method, forger_1_sign_key_to_bytes,
                                          forger_1_vrf_pub_key_to_bytes[0:32], forger_1_vrf_pub_key_to_bytes[32:],
                                          convertZenToWei(1))
            fail("withdraw call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger stake V2 has not been activated yet" in str(err))

        # Test that getForger and getPagedForgers fail before activate.
        method = 'getForger(bytes32,bytes32,bytes1)'
        forger_1_sign_key_to_bytes = hex_str_to_bytes(block_sign_pub_key_1)
        forger_1_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_1)
        forger_1_keys_to_bytes = (forger_1_sign_key_to_bytes, forger_1_vrf_pub_key_to_bytes[:32],
                                  forger_1_vrf_pub_key_to_bytes[32:])
        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method, *forger_1_keys_to_bytes)
            fail("getForger call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger stake V2 has not been activated yet" in str(err))

        method = 'getPagedForgers(int32,int32)'
        get_paged_forgers_args = (0, 100)
        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method, *get_paged_forgers_args)
            fail("getForger call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger stake V2 has not been activated yet" in str(err))

        # Test that getCurrentConsensusEpoch fails before activate.

        method = 'getCurrentConsensusEpoch()'
        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method)
            fail("getCurrentConsensusEpoch call should fail")
        except RuntimeError as err:
            print("Expected exception thrown: {}".format(err))
            assert_true("Forger stake V2 has not been activated yet" in str(err))

        # Check that stakeStart cannot be called before activate
        method = 'stakeStart(bytes32,bytes32,bytes1,address)'
        forger_1_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_1)

        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method, forger_1_sign_key_to_bytes,
                                          forger_1_vrf_pub_key_to_bytes[0:32], forger_1_vrf_pub_key_to_bytes[32:],
                                          "0x" + evm_address_sc_node_1)
            fail("stakeStart call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger stake V2 has not been activated yet" in str(err))

        # Check that after fork 1.4 but before activate, it is still possible to call makeForgerStake and
        # spendForgingStake

        make_forger_stake_json_res = ac_makeForgerStake(sc_node_1, evm_address_5, block_sign_pub_key_1,
                           vrf_pub_key_1, convertZenToZennies(4))

        if "result" not in make_forger_stake_json_res:
            fail("make forger stake with native smart contract v1 should work before activate")
        else:
            logging.info("Transaction created as expected")
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(len(orig_stake_list) + 1, len(stake_list))

        stake_id = stake_list[-1]['stakeId']
        spend_forger_stake_json_res = sc_node_1.transaction_spendForgingStake(
            json.dumps({"stakeId": stake_id}))
        if "result" not in spend_forger_stake_json_res:
            fail("spend forger stake failed: " + json.dumps(spend_forger_stake_json_res))
        else:
            logging.info("Forger stake removed: " + json.dumps(spend_forger_stake_json_res))
        self.sc_sync_all()

        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        # Execute activate.
        forger_stake_v2_balance = rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS)
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

        disable_event = tx_receipt['logs'][0]
        assert_equal(1, len(disable_event['topics']), "Wrong number of topics in disable_event")
        event_id = remove_0x_prefix(disable_event['topics'][0])
        event_signature = remove_0x_prefix(
            encode_hex(event_signature_to_log_topic('DisableStakeV1()')))
        assert_equal(event_signature, event_id, "Wrong event signature in topics")

        activate_event = tx_receipt['logs'][1]
        assert_equal(1, len(activate_event['topics']), "Wrong number of topics in activate_event")
        event_id = remove_0x_prefix(activate_event['topics'][0])
        event_signature = remove_0x_prefix(
            encode_hex(event_signature_to_log_topic('ActivateStakeV2()')))
        assert_equal(event_signature, event_id, "Wrong event signature in topics")

        # retrieve the stakes from the Forger Stake V2
        stake_list_node1 = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        stake_list_node2 = sc_node_2.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(stake_list_node1, stake_list_node2, "Forging stakes are different on 2 nodes")

        for stake in stake_list_node1:
            if stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_1:
                assert_equal(exp_stake_own_1, stake['forgerStakeData']['stakedAmount'],
                             "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_2:
                assert_equal(exp_stake_own_2, stake['forgerStakeData']['stakedAmount'],
                             "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_3:
                assert_equal(exp_stake_own_3, stake['forgerStakeData']['stakedAmount'],
                             "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_4:
                assert_equal(exp_stake_own_4, stake['forgerStakeData']['stakedAmount'],
                             "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_5:
                assert_equal(exp_stake_own_5, stake['forgerStakeData']['stakedAmount'],
                             "Forger stake is different after upgrade")
            else:
                assert_equal(genesis_stake, stake['forgerStakeData']['stakedAmount'],
                             "Forger stake is different after upgrade")
            assert_false('stakeId' in stake)

        # Test myForgingStakes(). On node 1 should return stakes belonging to evm_address_sc_node_1, evm_address_3, evm_address_5 and genesis.
        # On node 2 evm_address_sc_node_2 and evm_address_4.
        stake_list_node1 = sc_node_1.transaction_myForgingStakes()["result"]['stakes']
        for stake in stake_list_node1:
            if stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_1:
                assert_equal(exp_stake_own_1, stake['forgerStakeData']['stakedAmount'], "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_3:
                assert_equal(exp_stake_own_3, stake['forgerStakeData']['stakedAmount'], "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_5:
                assert_equal(exp_stake_own_5, stake['forgerStakeData']['stakedAmount'], "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_2:
                fail("returned stakes not belonging to an address of the node")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_4:
                fail("returned stakes not belonging to an address of the node")
            else:
                assert_equal(genesis_stake, stake['forgerStakeData']['stakedAmount'], "Forger stake is different after upgrade")
            assert_false('stakeId' in stake)

        stake_list_node2 = sc_node_2.transaction_myForgingStakes()["result"]['stakes']
        for stake in stake_list_node2:
            if stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_1:
                fail("returned stakes not belonging to an address of the node")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_3:
                fail("returned stakes not belonging to an address of the node")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_5:
                fail("returned stakes not belonging to an address of the node")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_sc_node_2:
                assert_equal(exp_stake_own_2, stake['forgerStakeData']['stakedAmount'], "Forger stake is different after upgrade")
            elif stake['forgerStakeData']['ownerPublicKey']['address'] == evm_address_4:
                assert_equal(exp_stake_own_4, stake['forgerStakeData']['stakedAmount'], "Forger stake is different after upgrade")
            else:
                fail("returned stakes not belonging to an address of the node")
            assert_false('stakeId' in stake)

        # Check the balance of the 2 smart contracts
        assert_equal(0, rpc_get_balance(sc_node_1, FORGER_STAKE_SMART_CONTRACT_ADDRESS))
        assert_equal(forger_stake_balance + forger_stake_v2_balance,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_stake_v2_balance += forger_stake_balance

        # Check that activate cannot be called twice

        try:
            contract_function_call(sc_node_1, forger_v2_native_contract,
                                   FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                   evm_address_sc_node_1, method)
            fail("activate call should fail")
        except RuntimeError as err:
            pass

        # Check that old native smart contract is disabled
        method = "getAllForgersStakes()"
        try:
            old_forger_native_contract.static_call(sc_node_1, method, fromAddress=evm_address_sc_node_1,
                                                   toAddress=FORGER_STAKE_SMART_CONTRACT_ADDRESS)
            fail("call should fail after activate of Forger Stake v2")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            # error is raised from API since the address has no balance
            assert_true("Method is disabled" in str(err))

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)

        # Check that after activate, calling makeForgerStake and spendForgingStake HTTP APIs is not possible anymore
        make_forger_stake_json_res = ac_makeForgerStake(sc_node_1, evm_address_5, block_sign_pub_key_1,
                                                        vrf_pub_key_1, convertZenToZennies(4))

        if "error" not in make_forger_stake_json_res:
            fail("make forger stake with native smart contract v1 should fail after activate")

        assert_equal("Method is disabled after Fork 1.4. Use Forger Stakes Native Smart Contract V2",
                     make_forger_stake_json_res['error']['description'])
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        spend_forger_stake_json_res = sc_node_1.transaction_spendForgingStake(
            json.dumps({"stakeId": stake_id}))
        if "error" not in spend_forger_stake_json_res:
            fail("spend forger stake failed: " + json.dumps(spend_forger_stake_json_res))
        assert_equal("Method is disabled after Fork 1.4. Use Forger Stakes Native Smart Contract V2",
                     spend_forger_stake_json_res['error']['description'])

        # Check getPagedForgers
        method = 'getPagedForgers(int32,int32)'
        data = forger_v2_native_contract.raw_encode_call(method, *get_paged_forgers_args)

        result = sc_node_1.rpc_eth_call(
            {
                "to": format_evm(FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS),
                "from": format_evm(evm_address_sc_node_1),
                "input": data
            }, "latest"
        )

        (next_pos, list_of_forgers) = decode_paged_list_of_forgers(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(1, len(list_of_forgers))
        assert_equal(block_sign_pub_key_1, list_of_forgers[0][0])
        assert_equal(vrf_pub_key_1, list_of_forgers[0][1])
        assert_equal(0, list_of_forgers[0][2])
        assert_equal(NULL_ADDRESS, list_of_forgers[0][3])

        # Check getForger
        method = 'getForger(bytes32,bytes32,bytes1)'
        data = forger_v2_native_contract.raw_encode_call(method, *forger_1_keys_to_bytes)

        result = sc_node_1.rpc_eth_call(
            {
                "to": format_evm(FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS),
                "from": format_evm(evm_address_sc_node_1),
                "input": data
            }, "latest"
        )

        forger_info = decode_forger_info(hex_str_to_bytes(result['result'][2:]))
        assert_equal(block_sign_pub_key_1, forger_info[0])
        assert_equal(vrf_pub_key_1, forger_info[1])
        assert_equal(0, forger_info[2])
        assert_equal(NULL_ADDRESS, forger_info[3])

        # Try getForger on a non-registered forger
        forger_2_sign_key_to_bytes = hex_str_to_bytes(block_sign_pub_key_2)
        forger_2_vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_2)
        forger_2_keys_to_bytes = (forger_2_sign_key_to_bytes, forger_2_vrf_pub_key_to_bytes[:32],
                                  forger_2_vrf_pub_key_to_bytes[32:])

        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, method, *forger_2_keys_to_bytes)
            fail("getForger call should fail if forger is not registered yet")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger doesn't exist." in str(err))

        ################################
        # Delegate
        ################################
        evm_address_sc_node_1_balance = rpc_get_balance(sc_node_1, evm_address_sc_node_1)

        staked_amount = convertZenToWei(1)

        delegate_method = 'delegate(bytes32,bytes32,bytes1)'

        tx_hash = contract_function_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_1, delegate_method, forger_1_sign_key_to_bytes,
                                         forger_1_vrf_pub_key_to_bytes[0:32], forger_1_vrf_pub_key_to_bytes[32:],
                                         value=staked_amount)

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        self.sc_sync_all()

        # Check the receipt and the event log
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')
        assert_equal(41403, int(tx_receipt['gasUsed'], 16), "wrong used gas")
        assert_equal(1, len(tx_receipt['logs']), 'Wrong number of logs')
        delegate_event = tx_receipt['logs'][0]
        check_delegate_event(delegate_event, evm_address_sc_node_1, forger_1_vrf_pub_key_to_bytes, block_sign_pub_key_1,
                             staked_amount)

        # Check the balance after delegate
        gas_fee_paid, _, _ = computeForgedTxFee(sc_node_1, tx_hash)
        assert_equal(evm_address_sc_node_1_balance - staked_amount - gas_fee_paid,
                     rpc_get_balance(sc_node_1, evm_address_sc_node_1))
        assert_equal(staked_amount + forger_stake_v2_balance,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_stake_v2_balance += staked_amount

        # Check stakes by forger
        method_paged_stakes_by_forger = "getPagedForgersStakesByForger(bytes32,bytes32,bytes1,int32,int32)"

        paged_stakes_by_forger_1_data_input = (forger_v2_native_contract.
                                               raw_encode_call(method_paged_stakes_by_forger,
                                                               forger_1_sign_key_to_bytes,
                                                               forger_1_vrf_pub_key_to_bytes[0:32],
                                                               forger_1_vrf_pub_key_to_bytes[32:], 0, 100))
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": paged_stakes_by_forger_1_data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_forger_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(6, len(list_of_stakes))

        exp_stake_own_1 += staked_amount
        assert_equal(exp_stake_own_1, list_of_stakes["0x" + evm_address_sc_node_1])
        assert_equal(exp_stake_own_2, list_of_stakes["0x" + evm_address_sc_node_2])
        assert_equal(exp_stake_own_3, list_of_stakes["0x" + evm_address_3])
        assert_equal(exp_stake_own_4, list_of_stakes["0x" + evm_address_4])
        assert_equal(exp_stake_own_5, list_of_stakes["0x" + evm_address_5])

        # Check stakes by delegator
        method_paged_stakes_by_delegator = "getPagedForgersStakesByDelegator(address,int32,int32)"

        data_input = forger_v2_native_contract.raw_encode_call(method_paged_stakes_by_delegator,
                                                               "0x" + evm_address_sc_node_1,
                                                               0, 100)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_delegator_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(1, len(list_of_stakes))
        assert_equal(block_sign_pub_key_1, list_of_stakes[0][0])
        assert_equal(vrf_pub_key_1, list_of_stakes[0][1])
        assert_equal(exp_stake_own_1, list_of_stakes[0][2])

        # Try delegate to a non-registered forger

        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_1, delegate_method,
                                          hex_str_to_bytes(block_sign_pub_key_2),
                                          forger_1_vrf_pub_key_to_bytes[0:32], forger_1_vrf_pub_key_to_bytes[32:],
                                          value=convertZenToWei(1))
            fail("delegate call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Forger doesn't exist" in str(err))

        # Check stakeStart
        method_stake_start = "stakeStart(bytes32,bytes32,bytes1,address)"
        data_input = forger_v2_native_contract.raw_encode_call(method_stake_start,
                                                               forger_1_sign_key_to_bytes,
                                                               forger_1_vrf_pub_key_to_bytes[0:32],
                                                               forger_1_vrf_pub_key_to_bytes[32:],
                                                               "0x" + evm_address_sc_node_1)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, "latest"
        )
        assert_equal(decode(['int32'], hex_str_to_bytes(result['result'][2:]))[0], VERSION_1_4_FORK_EPOCH)
        # Check stakeStart value for address that did not delegated anything - should return -1
        data_input = forger_v2_native_contract.raw_encode_call(method_stake_start,
                                                               forger_1_sign_key_to_bytes,
                                                               forger_1_vrf_pub_key_to_bytes[0:32],
                                                               forger_1_vrf_pub_key_to_bytes[32:],
                                                               "0x" + evm_address_sc_node_3)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, "latest"
        )
        assert_equal(decode(['int32'], hex_str_to_bytes(result['result'][2:]))[0], -1)

        ################################
        # Withdrawal
        ################################
        evm_address_sc_node_2_balance = rpc_get_balance(sc_node_1, evm_address_sc_node_2)

        staked_amount_withdrawn = exp_stake_own_2
        withdraw_method = "withdraw(bytes32,bytes32,bytes1,uint256)"

        tx_hash = contract_function_call(sc_node_2, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_2, withdraw_method, forger_1_sign_key_to_bytes,
                                         forger_1_vrf_pub_key_to_bytes[0:32], forger_1_vrf_pub_key_to_bytes[32:],
                                         staked_amount_withdrawn)

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        self.sc_sync_all()

        # Check the receipt and the event log
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')
        assert_equal(41503, int(tx_receipt['gasUsed'], 16), "wrong used gas")
        assert_equal(1, len(tx_receipt['logs']), 'Wrong number of logs')
        withdraw_event = tx_receipt['logs'][0]
        check_withdraw_event(withdraw_event, evm_address_sc_node_2, forger_1_vrf_pub_key_to_bytes, block_sign_pub_key_1,
                             staked_amount_withdrawn)

        # Check the balance after withdrawal
        gas_fee_paid, _, _ = computeForgedTxFee(sc_node_1, tx_hash)
        assert_equal(evm_address_sc_node_2_balance + staked_amount_withdrawn - gas_fee_paid,
                     rpc_get_balance(sc_node_1, evm_address_sc_node_2))
        assert_equal(forger_stake_v2_balance - staked_amount_withdrawn,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_stake_v2_balance -= staked_amount_withdrawn

        # Check stakes by forger
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": paged_stakes_by_forger_1_data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_forger_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(5, len(list_of_stakes))

        assert_equal(exp_stake_own_1, list_of_stakes["0x" + evm_address_sc_node_1])
        assert_equal(exp_stake_own_3, list_of_stakes["0x" + evm_address_3])
        assert_equal(exp_stake_own_4, list_of_stakes["0x" + evm_address_4])
        assert_equal(exp_stake_own_5, list_of_stakes["0x" + evm_address_5])

        assert_false(("0x" + evm_address_sc_node_2) in list_of_stakes)

        # Check stakes by delegator
        method_paged_stakes_by_delegator = "getPagedForgersStakesByDelegator(address,int32,int32)"

        data_input = forger_v2_native_contract.raw_encode_call(method_paged_stakes_by_delegator,
                                                               "0x" + evm_address_sc_node_2, 0, 100)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_delegator_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(0, len(list_of_stakes))

        # Try withdrawal without enough funds

        try:
            contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_2, withdraw_method,
                                          forger_1_sign_key_to_bytes,
                                          forger_1_vrf_pub_key_to_bytes[0:32], forger_1_vrf_pub_key_to_bytes[32:],
                                          staked_amount_withdrawn)
            fail("withdrawal call should fail")
        except RuntimeError as err:
            logging.info("Expected exception thrown: {}".format(err))
            assert_true("Not enough stake" in str(err))

        # Try getCurrentConsensusEpoch
        method = "getCurrentConsensusEpoch()"
        epoch = \
        contract_function_static_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                      evm_address_sc_node_2, method)[0]

        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        assert_equal(current_best_epoch, epoch)

        # Get the block hash of the tip at the current epoch
        block_id = sc_node_1.block_best()["result"]["block"]["id"]

        # Switch to a new epoch
        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        assert_false(epoch == current_best_epoch)
        rpc_tag = {
            "blockHash": "0x" + block_id
        }
        data_input = forger_v2_native_contract.raw_encode_call(method)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, rpc_tag
        )
        epoch_at_block = decode(['uint32'], hex_str_to_bytes(result['result'][2:]))[0]
        assert_equal(epoch, epoch_at_block)

        #######################################################################################################
        # Interoperability test with an EVM smart contract calling forger stakes V2 native contract
        #######################################################################################################

        # Create and deploy evm proxy contract
        # Create a new sc address to be used for the interoperability tests
        evm_address_interop = sc_node_1.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]

        new_ft_amount_in_zen = Decimal('50.0')

        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      evm_address_interop,
                                      new_ft_amount_in_zen,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=True)

        generate_next_block(sc_node_1, "first node")

        # Deploy proxy contract
        proxy_contract = SimpleProxyContract(sc_node_1, evm_address_interop, self.options.all_forks)

        # Send some funds to the proxy smart contract. Note that nonce=1 because evm_address_interop has deployed the proxy contract.
        contract_funds_in_zen = 10
        createEIP1559Transaction(sc_node_1, fromAddress=evm_address_interop,
                                 toAddress=format_eoa(proxy_contract.contract_address),
                                 nonce=1, gasLimit=230000, maxPriorityFeePerGas=900000000,
                                 maxFeePerGas=900000000, value=convertZenToWei(contract_funds_in_zen))
        generate_next_block(sc_node_1, "first node")

        # Call delegate using the proxy
        evm_address_interop_balance = rpc_get_balance(sc_node_1, evm_address_interop)

        proxy_contract_balance = rpc_get_balance(sc_node_1, proxy_contract.contract_address)

        native_input = format_eoa(
            forger_v2_native_contract.raw_encode_call(delegate_method, forger_1_sign_key_to_bytes,
                                                      forger_1_vrf_pub_key_to_bytes[0:32],
                                                      forger_1_vrf_pub_key_to_bytes[32:]))

        tx_hash = proxy_contract.call_transaction(evm_address_interop, 2, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                                  staked_amount, native_input)
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')
        assert_equal(183841, int(tx_receipt['gasUsed'], 16), "wrong used gas")
        assert_equal(1, len(tx_receipt['logs']), 'Wrong number of logs')
        delegate_event = tx_receipt['logs'][0]
        check_delegate_event(delegate_event, format_eoa(proxy_contract.contract_address), forger_1_vrf_pub_key_to_bytes,
                             block_sign_pub_key_1, staked_amount)

        # Check the balance after delegate
        gas_fee_paid, _, _ = computeForgedTxFee(sc_node_1, tx_hash)
        assert_equal(evm_address_interop_balance - gas_fee_paid, rpc_get_balance(sc_node_1, evm_address_interop))
        evm_address_interop_balance -= gas_fee_paid

        assert_equal(proxy_contract_balance - staked_amount,
                     rpc_get_balance(sc_node_1, proxy_contract.contract_address))
        proxy_contract_balance -= staked_amount

        assert_equal(staked_amount + forger_stake_v2_balance,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_stake_v2_balance += staked_amount

        # Check stakes by forger
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": paged_stakes_by_forger_1_data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_forger_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(6, len(list_of_stakes))

        assert_equal(exp_stake_own_1, list_of_stakes["0x" + evm_address_sc_node_1])
        assert_false(("0x" + evm_address_sc_node_2) in list_of_stakes)
        assert_equal(exp_stake_own_3, list_of_stakes["0x" + evm_address_3])
        assert_equal(exp_stake_own_4, list_of_stakes["0x" + evm_address_4])
        assert_equal(exp_stake_own_5, list_of_stakes["0x" + evm_address_5])
        assert_equal(staked_amount, list_of_stakes[proxy_contract.contract_address.lower()])

        # Check stakes by delegator
        data_input = forger_v2_native_contract.raw_encode_call(method_paged_stakes_by_delegator,
                                                               proxy_contract.contract_address,
                                                               0, 100)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_delegator_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(1, len(list_of_stakes))
        assert_equal(block_sign_pub_key_1, list_of_stakes[0][0])
        assert_equal(vrf_pub_key_1, list_of_stakes[0][1])
        assert_equal(staked_amount, list_of_stakes[0][2])

        # Call withdraw using the proxy

        native_input = format_eoa(
            forger_v2_native_contract.raw_encode_call(withdraw_method, forger_1_sign_key_to_bytes,
                                                      forger_1_vrf_pub_key_to_bytes[0:32],
                                                      forger_1_vrf_pub_key_to_bytes[32:], staked_amount))

        tx_hash = proxy_contract.call_transaction(evm_address_interop, 3, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                                  0, native_input)
        tx_receipt = generate_block_and_get_tx_receipt(sc_node_1, tx_hash)['result']

        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')
        assert_equal(48675, int(tx_receipt['gasUsed'], 16), "wrong used gas")
        assert_equal(1, len(tx_receipt['logs']), 'Wrong number of logs')
        withdraw_event = tx_receipt['logs'][0]
        check_withdraw_event(withdraw_event, format_eoa(proxy_contract.contract_address), forger_1_vrf_pub_key_to_bytes,
                             block_sign_pub_key_1, staked_amount)

        # Check the balance after withdrawal
        gas_fee_paid, _, _ = computeForgedTxFee(sc_node_1, tx_hash)
        assert_equal(evm_address_interop_balance - gas_fee_paid, rpc_get_balance(sc_node_1, evm_address_interop))
        evm_address_interop_balance -= gas_fee_paid

        assert_equal(proxy_contract_balance + staked_amount,
                     rpc_get_balance(sc_node_1, proxy_contract.contract_address))
        proxy_contract_balance += staked_amount

        assert_equal(forger_stake_v2_balance - staked_amount,
                     rpc_get_balance(sc_node_1, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS))
        forger_stake_v2_balance -= staked_amount_withdrawn

        # Check stakes by forger
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": paged_stakes_by_forger_1_data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_forger_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(5, len(list_of_stakes))

        assert_equal(exp_stake_own_1, list_of_stakes["0x" + evm_address_sc_node_1])
        assert_false(("0x" + evm_address_sc_node_2) in list_of_stakes)
        assert_equal(exp_stake_own_3, list_of_stakes["0x" + evm_address_3])
        assert_equal(exp_stake_own_4, list_of_stakes["0x" + evm_address_4])
        assert_equal(exp_stake_own_5, list_of_stakes["0x" + evm_address_5])
        assert_false((proxy_contract.contract_address.lower()) in list_of_stakes)

        # Check stakes by delegator
        data_input = forger_v2_native_contract.raw_encode_call(method_paged_stakes_by_delegator,
                                                               proxy_contract.contract_address,
                                                               0, 100)
        result = sc_node_1.rpc_eth_call(
            {
                "to": "0x" + FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                "from": add_0x_prefix(evm_address_sc_node_1),
                "input": data_input
            }, "latest"
        )

        (next_pos, list_of_stakes) = decode_paged_list_of_delegator_stakes(hex_str_to_bytes(result['result'][2:]))
        assert_equal(-1, next_pos)
        assert_equal(0, len(list_of_stakes))

        # Check getCurrentConsensusEpoch using proxy
        method = "getCurrentConsensusEpoch()"
        native_input = format_eoa(
            forger_v2_native_contract.raw_encode_call(method))

        result = proxy_contract.do_static_call(evm_address_interop, 3, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                               native_input)

        epoch = decode(['uint32'], result)[0]
        current_best_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        assert_equal(current_best_epoch, epoch)

        #######################################################################################################
        # Reward workflow test
        #######################################################################################################

        ft_pool_amount = 0.5
        ft_pool_amount_wei = convertZenToWei(ft_pool_amount)
        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      format_eoa(FORGER_POOL_RECIPIENT_ADDRESS),
                                      ft_pool_amount,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=False)
        mc_node.generate(1)
        generate_next_block(sc_node_1, "second node")
        # assert Forger Pool balance is updated
        forger_pool_balance = int(self.sc_nodes[0].rpc_eth_getBalance(format_evm(FORGER_POOL_RECIPIENT_ADDRESS), 'latest')['result'], 16)
        assert_equal(ft_pool_amount_wei, forger_pool_balance)
        mc_node.generate(19)

        sc_last_we_block_id = generate_next_block(sc_node_1, "first node")

        self.sc_sync_all()

        # assert Forger Pool balance is distributed
        forger_pool_balance = int(
            self.sc_nodes[0].rpc_eth_getBalance(format_evm(FORGER_POOL_RECIPIENT_ADDRESS), 'latest')['result'], 16)
        assert_equal(0, forger_pool_balance)

        payments = http_block_getFeePayments(sc_node_1, sc_last_we_block_id)['feePayments']
        assert_equal(forger_stake_list[0]['forgerStakeData']['ownerPublicKey']['address'], payments[0]['address']['address'])
        assert_equal(ft_pool_amount_wei, payments[0]['valueFromMainchain'])
        assert_equal(payments[0]['value'], payments[0]['valueFromMainchain'] + payments[0]['valueFromFees'])


def decode_paged_list_of_forgers(result):
    next_pos = decode(['int32'], result[0:32])[0]
    res = result[32:]
    res = res[32:]  # cut offset, don't care in this case
    num_of_stakes = int(bytes_to_hex_str(res[0:32]), 16)

    res = res[32:]  # cut the array length

    elem_size = 160  # 32 * 5
    list_of_elems = [res[i:i + elem_size] for i in range(0, num_of_stakes * elem_size, elem_size)]

    list_of_forgers = []
    for p in list_of_elems:
        forger_info = decode_forger_info(p)
        list_of_forgers.append(forger_info)

    return next_pos, list_of_forgers


def decode_forger_info(result):
    raw_stake = decode(['(bytes32,bytes32,bytes1,uint32,address)'], result)[0]
    forger_info = (bytes_to_hex_str(raw_stake[0]),
                   bytes_to_hex_str(raw_stake[1]) + bytes_to_hex_str(raw_stake[2]),
                   raw_stake[3], raw_stake[4])

    return forger_info


def sum_stakes(exp_stake_own):
    return sum(map(lambda stake: stake['forgerStakeData']['stakedAmount'], exp_stake_own))


def check_delegate_event(delegate_event, sender, vrf_pub_key, block_sign_pub_key, staked_amount):
    assert_equal(4, len(delegate_event['topics']), "Wrong number of topics in delegate_event")
    event_id = remove_0x_prefix(delegate_event['topics'][0])
    event_signature = remove_0x_prefix(
        encode_hex(event_signature_to_log_topic('DelegateForgerStake(address,bytes32,bytes32,bytes1,uint256)')))
    assert_equal(event_signature, event_id, "Wrong event signature in topics")

    from_addr = decode(['address'], hex_str_to_bytes(delegate_event['topics'][1][2:]))[0][2:]
    assert_equal(sender.lower(), from_addr.lower(), "Wrong from address in topics")

    vrf1 = decode(['bytes32'], hex_str_to_bytes(delegate_event['topics'][2][2:]))[0]
    vrf2 = decode(['bytes1'], hex_str_to_bytes(delegate_event['topics'][3][2:]))[0]

    assert_equal(bytes_to_hex_str(vrf_pub_key),
                 bytes_to_hex_str(vrf1) + bytes_to_hex_str(vrf2), "wrong vrfPublicKey")

    (sign_pub_key, value) = decode(['bytes32', 'uint256'], hex_str_to_bytes(delegate_event['data'][2:]))
    assert_equal(block_sign_pub_key, bytes_to_hex_str(sign_pub_key), "Wrong sign_pub_key in event")
    assert_equal(staked_amount, value, "Wrong amount in event")


def check_withdraw_event(event, sender, vrf_pub_key, block_sign_pub_key, staked_amount):
    assert_equal(4, len(event['topics']), "Wrong number of topics in withdraw_event")
    event_id = remove_0x_prefix(event['topics'][0])
    event_signature = remove_0x_prefix(
        encode_hex(event_signature_to_log_topic('WithdrawForgerStake(address,bytes32,bytes32,bytes1,uint256)')))
    assert_equal(event_signature, event_id, "Wrong event signature in topics")

    from_addr = decode(['address'], hex_str_to_bytes(event['topics'][1][2:]))[0][2:]
    assert_equal(sender.lower(), from_addr.lower(), "Wrong from address in topics")

    vrf1 = decode(['bytes32'], hex_str_to_bytes(event['topics'][2][2:]))[0]
    vrf2 = decode(['bytes1'], hex_str_to_bytes(event['topics'][3][2:]))[0]

    assert_equal(bytes_to_hex_str(vrf_pub_key),
                 bytes_to_hex_str(vrf1) + bytes_to_hex_str(vrf2), "wrong vrfPublicKey")

    (sign_pub_key, value) = decode(['bytes32', 'uint256'], hex_str_to_bytes(event['data'][2:]))
    assert_equal(block_sign_pub_key, bytes_to_hex_str(sign_pub_key), "Wrong sign_pub_key in event")
    assert_equal(staked_amount, value, "Wrong amount in event")


def decode_paged_list_of_forger_stakes(result):
    next_pos = decode(['int32'], result[0:32])[0]
    res = result[32:]
    res = res[32:]  # cut offset, don't care in this case
    num_of_stakes = int(bytes_to_hex_str(res[0:32]), 16)

    res = res[32:]  # cut the array length

    elem_size = 64  # 32 * 2
    list_of_elems = [res[i:i + elem_size] for i in range(0, num_of_stakes * elem_size, elem_size)]

    list_of_stakes = []
    for p in list_of_elems:
        list_of_stakes.append(decode(['(address,uint256)'], p)[0])

    return next_pos, dict(list_of_stakes)


def decode_paged_list_of_delegator_stakes(result):
    next_pos = decode(['int32'], result[0:32])[0]
    res = result[32:]
    res = res[32:]  # cut offset, don't care in this case
    num_of_stakes = int(bytes_to_hex_str(res[0:32]), 16)

    res = res[32:]  # cut the array length

    elem_size = 128  # 32 * 4
    list_of_elems = [res[i:i + elem_size] for i in range(0, num_of_stakes * elem_size, elem_size)]

    list_of_stakes = []
    for p in list_of_elems:
        raw_stake = decode(['(bytes32,bytes32,bytes1,uint256)'], p)[0]
        stake = (bytes_to_hex_str(raw_stake[0]),
                 bytes_to_hex_str(raw_stake[1]) + bytes_to_hex_str(raw_stake[2]),
                 raw_stake[3])
        list_of_stakes.append(stake)

    return next_pos, list_of_stakes


if __name__ == "__main__":
    SCEvmNativeForgerV2().main()
