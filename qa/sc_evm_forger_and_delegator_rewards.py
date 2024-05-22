#!/usr/bin/env python3
import json
import logging
import time

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import ac_makeForgerStake, format_eoa, contract_function_call, \
    ac_updateForger
from SidechainTestFramework.account.httpCalls.wallet.balance import http_wallet_balance
from SidechainTestFramework.account.utils import convertZenToZennies, convertZenniesToWei, convertZenToWei, \
    computeForgedTxFee, FORGER_POOL_RECIPIENT_ADDRESS, FORGER_STAKE_SMART_CONTRACT_ADDRESS, \
    FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS
from SidechainTestFramework.sc_boostrap_info import SCNodeConfiguration, MCConnectionInfo, SCNetworkConfiguration, \
    SCCreationInfo, SCForgerConfiguration
from SidechainTestFramework.sc_forging_util import check_mcreference_presence
from SidechainTestFramework.scutil import (
    connect_sc_nodes, generate_next_block, SLOTS_IN_EPOCH, EVM_APP_SLOT_TIME,
    bootstrap_sidechain_nodes, AccountModel, generate_next_blocks, )
from httpCalls.block.getFeePayments import http_block_getFeePayments
from test_framework.util import (
    assert_equal, fail, forward_transfer_to_sidechain, assert_false, websocket_port_by_mc_node_index,
)

"""
Check Forger fee payments:
1. Forging using stakes of different SC nodes
Configuration:
    - forger 1 - reward 1 - delegator 1 - share 500
    - forger 2 - reward 1 - delegator 2 - share 500
    - forger 3 - reward 3 - delegator 3 - share 500
    - forger 4 - reward 4 - delegator 3 - share 500
    - forger 5 - reward 5 - null         - null         - not upgraded
    - forger 6 - reward 6 - delegator 6 - share 1000
    - forger 7 - reward 7 == delegator 7 - share 500
Test:
    - advance to epoch 67
    - send funds to new address at node 1, advance to 68
    - send some zen to 6 forgers, forge required blocks to create 6 new forger stakes
    - reach fork 1.3, execute upgrade
    - test block forging, reach epoch 79
    - send 1000 zen to mc_reward_pool
    - distribute fees, ignore the results
    - send 100 zen to mc_reward_pool
    - forger stake is activated
    - forgers are upgraded
    - distribute fees
        - forger rewards:
            - forger 1 <1.4 - 2/16 of mc_reward_pool + 2/16 block_fees + 2 zennies remainder
            - forger 1 >1.4 - 3/16 of mc_reward_pool + 3/16 block_fees + tips + 2 zennies remainder
            - forger 2      - 3/16 of mc_reward_pool + 3/16 block_fees + 2 zennies remainder
            - forger 3      - 2/16 of mc_reward_pool + 2/16 block_fees
            - forger 4      - 2/16 of mc_reward_pool + 2/16 block_fees
            - forger 5      - 2/16 of mc_reward_pool + 2/16 block_fees
            - forger 6      - 1/16 of mc_reward_pool + 1/16 block_fees
            - forger 7      - 1/16 of mc_reward_pool + 1/16 block_fees

        - reward 1 gets
            - 100% from forger 1 before fork
            - 50% from forger 1 after fork
            - 50% from forger 2
        - reward 3 gets
            - 50% from forger 3
        - reward 4 gets
            - 50% from forger 4
        - reward 5 gets
            - 100% from forger 5
        - reward 6 gets 0
        - reward 7 gets
            - 100% from forger 7(as it is == to delegator 7)

        - delegator 1 gets
            - 50% from forger 1 after fork
        - delegator 2 gets
            - 50% from forger 2
        - delegator 3 gets
            - 50% from forger 3
            - 50% from forger 4
        - delegator 6 gets
            - 100% from forger 6
        - delegator 7 gets
            - 100% from forger 7(as it is == to reward 7)

    This test doesn't support --allforks.
"""


class ScEvmForgerAndDelegetorRewards(AccountChainSetup):
    FORGER_REWARD_ADDRESS_1 = '0000000000000000000012341234123412341111'
    FORGER_REWARD_ADDRESS_3 = '0000000000000000000012341234123412343333'
    FORGER_REWARD_ADDRESS_4 = '0000000000000000000012341234123412344444'
    FORGER_REWARD_ADDRESS_5 = '0000000000000000000012341234123412345555'
    FORGER_REWARD_ADDRESS_6 = '0000000000000000000012341234123412346666'
    FORGER_REWARD_ADDRESS_7 = '0000000000000000000012341234123412347777'
    DELEGATOR_ADDRESS_1 = '0000000000000000000056785678567856781111'
    DELEGATOR_ADDRESS_2 = '0000000000000000000056785678567856782222'
    DELEGATOR_ADDRESS_3 = '0000000000000000000056785678567856783333'
    DELEGATOR_ADDRESS_5 = '0000000000000000000056785678567856784444'
    DELEGATOR_ADDRESS_6 = '0000000000000000000056785678567856785555'
    DELEGATOR_ADDRESS_7 = FORGER_REWARD_ADDRESS_7

    def __init__(self):
        super().__init__(number_of_sidechain_nodes=7, withdrawalEpochLength=20, forward_amount=50,
                         block_timestamp_rewind=SLOTS_IN_EPOCH * EVM_APP_SLOT_TIME * 100)

    def run_test(self):
        if self.options.all_forks:
            logging.info("This test cannot be executed with --allforks")
            exit()

        mc_node = self.nodes[0]
        sc_node_1 = self.sc_nodes[0]
        sc_node_2 = self.sc_nodes[1]
        sc_node_3 = self.sc_nodes[2]
        sc_node_4 = self.sc_nodes[3]
        sc_node_5 = self.sc_nodes[4]
        sc_node_6 = self.sc_nodes[5]
        sc_node_7 = self.sc_nodes[6]
        connect_sc_nodes(sc_node_1, 1)
        self.sc_sync_all()
        self.advance_to_epoch(67)
        self.sync_all()
        self.sc_sync_all()

        # mc_node.generate(self.withdrawalEpochLength)
        # # trigger cert submission
        # # Generate 2 SC blocks on SC node and start them automatic cert creation.
        # generate_next_block(sc_node_1, "first node")  # 1 SC block to reach the end of WE
        # generate_next_block(sc_node_1, "first node")  # 1 SC block to trigger Submitter logic
        # # Wait for Certificates appearance
        # time.sleep(10)
        # while mc_node.getmempoolinfo()["size"] < 1 and sc_node_1.submitter_isCertGenerationActive()["result"][
        #     "state"]:
        #     logging.info("Wait for certificates in the MC mempool...")
        #     if sc_node_1.submitter_isCertGenerationActive()["result"]["state"]:
        #         logging.info("sc_node generating certificate now.")
        #     time.sleep(2)
        # assert_equal(1, mc_node.getmempoolinfo()["size"], "Certificates was not added to MC node mempool.")

        # transfer some fund from MC to SC1 at a new evm address, then mine mc block
        evm_address_sc_node_1 = sc_node_1.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]
        ft_amount_in_zen = 1000
        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      evm_address_sc_node_1,
                                      ft_amount_in_zen,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=False)

        mc_node.generate(1)
        self.sync_all()
        generate_next_block(sc_node_1, "first", force_switch_to_next_epoch=True)  # 68
        self.sc_sync_all()

        # Create forgers addresses. Send zen to forgers, Create forger stakes
        forger_stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        forger_1_blockSignPubKey = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["blockSignPublicKey"]["publicKey"]
        forger_1_vrfPubKey = forger_stake_list[0]['forgerStakeData']["forgerPublicKeys"]["vrfPublicKey"]["publicKey"]
        forger_2_address, forger_2_blockSignPubKey, forger_2_vrfPubKey = self.create_forger_stake(mc_node, sc_node_2, 13, 11)
        forger_3_address, forger_3_blockSignPubKey, forger_3_vrfPubKey = self.create_forger_stake(mc_node, sc_node_3, 13, 11)
        forger_4_address, forger_4_blockSignPubKey, forger_4_vrfPubKey = self.create_forger_stake(mc_node, sc_node_4, 13, 11)
        forger_5_address, forger_5_blockSignPubKey, forger_5_vrfPubKey = self.create_forger_stake(mc_node, sc_node_5, 13, 11)
        forger_6_address, forger_6_blockSignPubKey, forger_6_vrfPubKey = self.create_forger_stake(mc_node, sc_node_6, 13, 11)
        forger_7_address, forger_7_blockSignPubKey, forger_7_vrfPubKey = self.create_forger_stake(mc_node, sc_node_7, 13, 11)
        self.sc_sync_all()

        # we now have 7 stakes, one from creation and 6 just added
        stakeList = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(7, len(stakeList))

        # reach fork point 1.3 and execute stake v1 upgrade
        generate_next_block(sc_node_1, "first", force_switch_to_next_epoch=True)  # 69
        generate_next_block(sc_node_1, "first", force_switch_to_next_epoch=True)  # 70
        # Execute upgrade
        old_forger_native_contract = SmartContract("ForgerStakes")
        method = 'upgrade()'
        contract_function_call(sc_node_1, old_forger_native_contract, FORGER_STAKE_SMART_CONTRACT_ADDRESS,
                               evm_address_sc_node_1, method)

        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)  # 71
        self.sc_sync_all()

        # Assert block creation by each node
        generate_next_block(sc_node_2, "second")
        generate_next_block(sc_node_3, "third")
        generate_next_block(sc_node_4, "fourth")
        generate_next_block(sc_node_5, "fifth")
        generate_next_block(sc_node_6, "sixth")
        generate_next_block(sc_node_7, "seventh")

        # Reach epoch 79
        self.advance_to_epoch(79)
        # Send 100 zen to forger pool mc reward address
        ft_pool_amount = 1000
        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      format_eoa(FORGER_POOL_RECIPIENT_ADDRESS),
                                      ft_pool_amount,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=False)
        mc_node.generate(self.withdrawalEpochLength - 7)
        self.sync_all()
        self.sc_sync_all()
        sc_last_we_block_id = generate_next_block(sc_node_1, "third node")
        self.sc_sync_all()

        # Check that the fee distribution took place, exact fees before 1.4 are not tested here
        api_fee_payments = http_block_getFeePayments(sc_node_1, sc_last_we_block_id)['feePayments']
        # 7 because the genesis block is counted towards node 1 forger address, not reward address
        assert_equal(7, len(api_fee_payments))

        # trigger cert submission
        # Generate 2 SC blocks on SC node and start them automatic cert creation.
        generate_next_block(sc_node_1, "first node")
        generate_next_block(sc_node_1, "first node")  # 1 SC block to trigger Submitter logic
        # Wait for Certificates appearance
        time.sleep(10)
        while mc_node.getmempoolinfo()["size"] < 1 and sc_node_1.submitter_isCertGenerationActive()["result"][
            "state"]:
            logging.info("Wait for certificates in the MC mempool...")
            if sc_node_1.submitter_isCertGenerationActive()["result"]["state"]:
                logging.info("sc_node generating certificate now.")
            time.sleep(2)
        assert_equal(1, mc_node.getmempoolinfo()["size"], "Certificates was not added to MC node mempool.")
        mc_node.generate(1)
        self.sync_all()
        self.sc_sync_all()

        # Generate some blocks for fee distribution calculation
        generate_next_block(sc_node_1, "first", force_switch_to_next_epoch=True)  # 80
        ft_pool_amount = 100
        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      format_eoa(FORGER_POOL_RECIPIENT_ADDRESS),
                                      ft_pool_amount,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=False)
        # Activate forger stake v2
        # Generates 2 blocks by node 1
        forger_pool_fee_1, node_1_tip_1 = self.activate_stake_v2(evm_address_sc_node_1, sc_node_1)

        # update forger
        update_tx_1 = ac_updateForger(sc_node_1, forger_1_blockSignPubKey, forger_1_vrfPubKey, reward_address=self.DELEGATOR_ADDRESS_1, reward_share=500)['result']['transactionId']
        update_tx_2 = ac_updateForger(sc_node_2, forger_2_blockSignPubKey, forger_2_vrfPubKey, reward_address=self.DELEGATOR_ADDRESS_2, reward_share=500)['result']['transactionId']
        update_tx_3 = ac_updateForger(sc_node_3, forger_3_blockSignPubKey, forger_3_vrfPubKey, reward_address=self.DELEGATOR_ADDRESS_3, reward_share=500)['result']['transactionId']
        update_tx_4 = ac_updateForger(sc_node_4, forger_4_blockSignPubKey, forger_4_vrfPubKey, reward_address=self.DELEGATOR_ADDRESS_3, reward_share=500)['result']['transactionId']
        update_tx_6 = ac_updateForger(sc_node_6, forger_6_blockSignPubKey, forger_6_vrfPubKey, reward_address=self.DELEGATOR_ADDRESS_6, reward_share=1000)['result']['transactionId']
        update_tx_7 = ac_updateForger(sc_node_7, forger_7_blockSignPubKey, forger_7_vrfPubKey, reward_address=self.DELEGATOR_ADDRESS_7, reward_share=500)['result']['transactionId']

        self.sc_sync_all()
        generate_next_block(sc_node_2, "second")
        _, forger_pool_fee_2, node_2_tip_2 = computeForgedTxFee(sc_node_1, update_tx_1)
        _, forger_pool_fee_3, node_2_tip_3 = computeForgedTxFee(sc_node_1, update_tx_2)
        _, forger_pool_fee_4, node_2_tip_4 = computeForgedTxFee(sc_node_1, update_tx_3)
        _, forger_pool_fee_5, node_2_tip_5 = computeForgedTxFee(sc_node_1, update_tx_4)
        _, forger_pool_fee_6, node_2_tip_6 = computeForgedTxFee(sc_node_1, update_tx_6)
        _, forger_pool_fee_7, node_2_tip_7 = computeForgedTxFee(sc_node_1, update_tx_7)
        generate_next_blocks(sc_node_2, "second", 1)
        generate_next_blocks(sc_node_3, "third", 2)
        generate_next_blocks(sc_node_4, "fourth", 2)
        generate_next_blocks(sc_node_5, "fifth", 2)
        generate_next_blocks(sc_node_6, "sixth", 1)
        generate_next_blocks(sc_node_7, "seventh", 1)

        mc_node.generate(self.withdrawalEpochLength - 1)

        # Fee calculations
        total_block_fee = forger_pool_fee_1 + forger_pool_fee_2 + forger_pool_fee_3 + forger_pool_fee_4 + forger_pool_fee_5 + forger_pool_fee_6 + forger_pool_fee_7
        per_block_fee = total_block_fee // 16
        block_fee_remainder = total_block_fee % 16
        node_1_before_fork_remainder, node_1_after_fork_remainder, node_2_remainder, \
            node_3_remainder, node_4_remainder, node_5_remainder, node_6_remainder, node_7_remainder = self.calculate_remainders(block_fee_remainder)

        total_node_1_tips = node_1_tip_1
        total_node_2_tips = node_2_tip_2 + node_2_tip_3 + node_2_tip_4 + node_2_tip_5 + node_2_tip_6 + node_2_tip_7
        per_block_mc_reward = convertZenniesToWei(2500000000) // 16  # 1,562,500,000,000,000,000

        forger_1_before_fork_rewards_mc = per_block_mc_reward * 2
        forger_1_before_fork_rewards_fee = per_block_fee * 2 + node_1_before_fork_remainder
        forger_1_before_fork_rewards = forger_1_before_fork_rewards_mc + forger_1_before_fork_rewards_fee
        forger_1_after_fork_rewards_mc = per_block_mc_reward * 3
        forger_1_after_fork_rewards_fee = per_block_fee * 3 + total_node_1_tips + node_1_after_fork_remainder
        forger_1_after_fork_rewards = forger_1_after_fork_rewards_mc + forger_1_after_fork_rewards_fee
        forger_2_rewards_mc = per_block_mc_reward * 3
        forger_2_rewards_fee = per_block_fee * 3 + total_node_2_tips + node_2_remainder
        forger_2_rewards = forger_2_rewards_mc + forger_2_rewards_fee
        forger_3_rewards_mc = per_block_mc_reward * 2
        forger_3_rewards_fee = per_block_fee * 2 + node_3_remainder
        forger_3_rewards = forger_3_rewards_mc + forger_3_rewards_fee
        forger_4_rewards_mc = per_block_mc_reward * 2
        forger_4_rewards_fee = per_block_fee * 2 + node_4_remainder
        forger_4_rewards = forger_4_rewards_mc + forger_4_rewards_fee
        forger_5_rewards_mc = per_block_mc_reward * 2
        forger_5_rewards_fee = per_block_fee * 2 + node_5_remainder
        forger_5_rewards = forger_5_rewards_mc + forger_5_rewards_fee
        forger_6_rewards_mc = per_block_mc_reward * 1
        forger_6_rewards_fee = per_block_fee * 1 + node_6_remainder
        forger_6_rewards = forger_6_rewards_mc + forger_6_rewards_fee
        forger_7_rewards_mc = per_block_mc_reward * 1
        forger_7_rewards_fee = per_block_fee * 1 + node_7_remainder
        forger_7_rewards = forger_7_rewards_mc + forger_7_rewards_fee

        reward_address_1_rewards = forger_1_before_fork_rewards + (forger_1_after_fork_rewards // 2) + (forger_2_rewards // 2) + (forger_1_after_fork_rewards % 2) + (forger_2_rewards % 2)
        reward_address_1_rewards_mc = forger_1_before_fork_rewards_mc + (forger_1_after_fork_rewards_mc // 2) + (forger_2_rewards_mc // 2) + (forger_1_after_fork_rewards_mc % 2) + (forger_2_rewards_mc % 2)
        reward_address_1_rewards_fee = forger_1_before_fork_rewards_fee + (forger_1_after_fork_rewards_fee // 2) + (forger_2_rewards_fee // 2) + (forger_1_after_fork_rewards_fee % 2) + (forger_2_rewards_fee % 2)
        reward_address_3_rewards = forger_3_rewards // 2 + forger_3_rewards % 2
        reward_address_3_rewards_mc = forger_3_rewards_mc // 2 + forger_3_rewards_mc % 2
        reward_address_3_rewards_fee = forger_3_rewards_fee // 2 + forger_3_rewards_fee % 2
        reward_address_4_rewards = forger_4_rewards // 2 + forger_4_rewards % 2
        reward_address_4_rewards_mc = forger_4_rewards_mc // 2 + forger_4_rewards_mc % 2
        reward_address_4_rewards_fee = forger_4_rewards_fee // 2 + forger_4_rewards_fee % 2
        reward_address_5_rewards = forger_5_rewards
        reward_address_7_rewards = forger_7_rewards

        delegator_address_1_rewards = forger_1_after_fork_rewards // 2
        delegator_address_2_rewards = forger_2_rewards // 2
        delegator_address_3_rewards = (forger_3_rewards // 2) + (forger_4_rewards // 2)
        delegator_address_6_rewards = forger_6_rewards

        sc_last_we_block_id = generate_next_block(sc_node_2, "second")
        api_fee_payments = http_block_getFeePayments(sc_node_1, sc_last_we_block_id)['feePayments']
        assert_equal(9, len(api_fee_payments))

        api_fee_payments_reward_1 = [f for f in api_fee_payments if f['address']['address'] == self.FORGER_REWARD_ADDRESS_1][0]
        assert_equal(reward_address_1_rewards, api_fee_payments_reward_1['value'])
        assert_equal(reward_address_1_rewards_mc, api_fee_payments_reward_1['valueFromMainchain'])
        assert_equal(reward_address_1_rewards_fee, api_fee_payments_reward_1['valueFromFees'])

        api_fee_payments_reward_3 = [f for f in api_fee_payments if f['address']['address'] == self.FORGER_REWARD_ADDRESS_3][0]
        assert_equal(reward_address_3_rewards, api_fee_payments_reward_3['value'])
        assert_equal(reward_address_3_rewards_mc, api_fee_payments_reward_3['valueFromMainchain'])
        assert_equal(reward_address_3_rewards_fee, api_fee_payments_reward_3['valueFromFees'])

        api_fee_payments_reward_4 = [f for f in api_fee_payments if f['address']['address'] == self.FORGER_REWARD_ADDRESS_4][0]
        assert_equal(reward_address_4_rewards, api_fee_payments_reward_4['value'])
        assert_equal(reward_address_4_rewards_mc, api_fee_payments_reward_4['valueFromMainchain'])
        assert_equal(reward_address_4_rewards_fee, api_fee_payments_reward_4['valueFromFees'])

        api_fee_payments_reward_5 = [f for f in api_fee_payments if f['address']['address'] == self.FORGER_REWARD_ADDRESS_5][0]
        assert_equal(reward_address_5_rewards, api_fee_payments_reward_5['value'])
        assert_equal(forger_5_rewards_mc, api_fee_payments_reward_5['valueFromMainchain'])
        assert_equal(forger_5_rewards_fee, api_fee_payments_reward_5['valueFromFees'])

        api_fee_payments_reward_7 = [f for f in api_fee_payments if f['address']['address'] == self.FORGER_REWARD_ADDRESS_7][0]
        assert_equal(reward_address_7_rewards, api_fee_payments_reward_7['value'])
        assert_equal(forger_7_rewards_mc, api_fee_payments_reward_7['valueFromMainchain'])
        assert_equal(forger_7_rewards_fee, api_fee_payments_reward_7['valueFromFees'])

        api_fee_payments_delegator_1 = [f for f in api_fee_payments if f['address']['address'] == self.DELEGATOR_ADDRESS_1][0]
        assert_equal(delegator_address_1_rewards, api_fee_payments_delegator_1['value'])
        assert_equal(forger_1_after_fork_rewards_mc // 2, api_fee_payments_delegator_1['valueFromMainchain'])
        assert_equal(forger_1_after_fork_rewards_fee // 2, api_fee_payments_delegator_1['valueFromFees'])

        api_fee_payments_delegator_2 = [f for f in api_fee_payments if f['address']['address'] == self.DELEGATOR_ADDRESS_2][0]
        assert_equal(delegator_address_2_rewards, api_fee_payments_delegator_2['value'])
        assert_equal(forger_2_rewards_mc // 2, api_fee_payments_delegator_2['valueFromMainchain'])
        assert_equal(forger_2_rewards_fee // 2, api_fee_payments_delegator_2['valueFromFees'])

        api_fee_payments_delegator_3 = [f for f in api_fee_payments if f['address']['address'] == self.DELEGATOR_ADDRESS_3][0]
        assert_equal(delegator_address_3_rewards, api_fee_payments_delegator_3['value'])
        assert_equal((forger_3_rewards_mc + forger_4_rewards_mc) // 2, api_fee_payments_delegator_3['valueFromMainchain'])
        assert_equal((forger_3_rewards_fee + forger_4_rewards_fee) // 2, api_fee_payments_delegator_3['valueFromFees'])

        api_fee_payments_delegator_6 = [f for f in api_fee_payments if f['address']['address'] == self.DELEGATOR_ADDRESS_6][0]
        assert_equal(delegator_address_6_rewards, api_fee_payments_delegator_6['value'])
        assert_equal(forger_6_rewards_mc, api_fee_payments_delegator_6['valueFromMainchain'])
        assert_equal(forger_6_rewards_fee, api_fee_payments_delegator_6['valueFromFees'])

        self.sc_sync_all()

    def activate_stake_v2(self, evm_address_sc_node_1, sc_node_1):
        forger_v2_native_contract = SmartContract("ForgerStakesV2")
        method = 'activate()'
        tx_hash = contract_function_call(sc_node_1, forger_v2_native_contract, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                         evm_address_sc_node_1, method)
        generate_next_block(sc_node_1, "first node")
        _, forgersPoolFee, forgerTip = computeForgedTxFee(sc_node_1, tx_hash)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        tx_receipt = sc_node_1.rpc_eth_getTransactionReceipt(tx_hash)['result']
        assert_equal('0x1', tx_receipt['status'], 'Transaction failed')
        intrinsic_gas = 21000 + 4 * 16  # activate signature are 4 non-zero bytes
        assert_equal(intrinsic_gas, int(tx_receipt['gasUsed'], 16), "wrong used gas")
        return forgersPoolFee, forgerTip

    def create_forger_stake(
            self,
            mc_node,
            sc_node,
            ft_amount_in_zen,
            forger_stake_amount):
        address = sc_node.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]
        block_sign_pub_key = sc_node.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key = sc_node.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]
        ft_amount_in_zennies = convertZenToZennies(ft_amount_in_zen)
        ft_amount_in_wei = convertZenniesToWei(ft_amount_in_zennies)
        forward_transfer_to_sidechain(self.sc_nodes_bootstrap_info.sidechain_id,
                                      mc_node,
                                      address,
                                      ft_amount_in_zen,
                                      mc_return_address=mc_node.getnewaddress(),
                                      generate_block=False)
        self.sync_all()
        assert_equal(1, mc_node.getmempoolinfo()["size"], "Forward Transfer expected to be added to mempool.")
        # Generate MC block and SC block
        mcblock_hash1 = mc_node.generate(1)[0]
        scblock_id1 = generate_next_block(self.sc_nodes[0], "first node")
        check_mcreference_presence(mcblock_hash1, scblock_id1, self.sc_nodes[0])
        self.sc_sync_all()
        # balance is in wei
        initial_balance_2 = http_wallet_balance(sc_node, address)
        assert_equal(ft_amount_in_wei, initial_balance_2)
        # Create forger stake with some Zen for SC node
        forger_stake_amount_in_wei = convertZenToWei(forger_stake_amount)
        makeForgerStakeJsonRes = ac_makeForgerStake(sc_node, address, block_sign_pub_key,
                                                    vrf_pub_key,
                                                    convertZenToZennies(forger_stake_amount))
        if "result" not in makeForgerStakeJsonRes:
            fail("make forger stake failed: " + json.dumps(makeForgerStakeJsonRes))
        else:
            logging.info("Forger stake created: " + json.dumps(makeForgerStakeJsonRes))
        self.sc_sync_all()

        tx_hash_0 = makeForgerStakeJsonRes['result']['transactionId']
        # Generate SC block
        generate_next_block(self.sc_nodes[0], "first node")
        self.sc_sync_all()
        transactionFee_0, forgersPoolFee, forgerTip = computeForgedTxFee(self.sc_nodes[0], tx_hash_0)
        # balance now is initial (ft) minus forgerStake and fee
        assert_equal(
            ft_amount_in_wei -
            (forger_stake_amount_in_wei + transactionFee_0),
            sc_node.wallet_getTotalBalance()['result']['balance']
        )
        return address, block_sign_pub_key, vrf_pub_key

    def advance_to_epoch(self, epoch_number: int):
        sc_node = self.sc_nodes[0]
        forging_info = sc_node.block_forgingInfo()
        current_epoch = forging_info["result"]["bestBlockEpochNumber"]
        # make sure we are not already passed the desired epoch
        assert_false(current_epoch > epoch_number, "unexpected epoch number")
        while current_epoch < epoch_number:
            generate_next_block(sc_node, "first node", force_switch_to_next_epoch=True)
            self.sc_sync_all()
            forging_info = sc_node.block_forgingInfo()
            current_epoch = forging_info["result"]["bestBlockEpochNumber"]

    def sc_setup_chain(self):
        mc_node = self.nodes[0]
        sc_node_configuration = [
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_1),
                api_key='Horizen',
                cert_submitter_enabled=True),
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_1),
                api_key='Horizen',
                cert_submitter_enabled=False),
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_3),
                api_key='Horizen',
                cert_submitter_enabled=False),
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_4),
                api_key='Horizen',
                cert_submitter_enabled=False),
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_5),
                api_key='Horizen',
                cert_submitter_enabled=False),
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_6),
                api_key='Horizen',
                cert_submitter_enabled=False),
            SCNodeConfiguration(
                MCConnectionInfo(address="ws://{0}:{1}".format(mc_node.hostname, websocket_port_by_mc_node_index(0))),
                forger_options=SCForgerConfiguration(forger_reward_address=self.FORGER_REWARD_ADDRESS_7),
                api_key='Horizen',
                cert_submitter_enabled=False),
        ]

        network = SCNetworkConfiguration(SCCreationInfo(mc_node, 3, 20), *sc_node_configuration)
        self.sc_nodes_bootstrap_info = \
            bootstrap_sidechain_nodes(self.options, network,
                                      block_timestamp_rewind=SLOTS_IN_EPOCH * EVM_APP_SLOT_TIME * 100,
                                      model=AccountModel)

    def calculate_remainders(self, block_fee_remainder):
        # block order: 1^, 1^, 1, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 7, 2
        if block_fee_remainder <= 2:
            return block_fee_remainder, 0, 0, 0, 0, 0, 0, 0
        if block_fee_remainder <= 5:
            return 2, block_fee_remainder - 2, 0, 0, 0, 0, 0, 0
        elif block_fee_remainder <= 7:
            return 2, 3, block_fee_remainder - 5, 0, 0, 0, 0, 0
        elif block_fee_remainder <= 9:
            return 2, 3, 2, block_fee_remainder - 7, 0, 0, 0, 0
        elif block_fee_remainder <= 11:
            return 2, 3, 2, 2, block_fee_remainder - 9, 0, 0, 0
        elif block_fee_remainder <= 13:
            return 2, 3, 2, 2, 2, block_fee_remainder - 11, 0, 0
        elif block_fee_remainder == 14:
            return 2, 3, 2, 2, 2, 2, 1, 0
        elif block_fee_remainder == 15:
            return 2, 3, 2, 2, 2, 2, 1, 1


if __name__ == "__main__":
    ScEvmForgerAndDelegetorRewards().main()
