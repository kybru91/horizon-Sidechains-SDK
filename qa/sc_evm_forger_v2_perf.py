#!/usr/bin/env python3
import logging
import time
from decimal import Decimal

from eth_utils import add_0x_prefix

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.ac_utils import generate_block_and_get_tx_receipt, contract_function_call, \
    ac_registerForger, contract_function_static_call
from SidechainTestFramework.account.utils import convertZenToZennies, FORGER_STAKE_SMART_CONTRACT_ADDRESS, \
    VERSION_1_3_FORK_EPOCH, \
    VERSION_1_4_FORK_EPOCH, FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS, convertZenniesToWei
from SidechainTestFramework.scutil import generate_next_block, EVM_APP_SLOT_TIME
from sc_evm_forger import print_current_epoch_and_slot
from test_framework.util import (
    assert_equal, forward_transfer_to_sidechain, hex_str_to_bytes, )

"""
This is a script for testing performance of the Forgers Lottery and of stakeTotal method.
For the Lottery, it it needs to enable sidechain logging level to debug and --nocleanup, for saving the logging files.
Then using grep command, retrieve all the lines with "Lottery times". The first
value is the epoch, the second one is the time taken to create the Merkle path, the third one is the lottery total time,
 i.e. Merkle path + vrfProofCheckAgainstStake. Retrieve the data from both nodes, sc_node_1 has 99 forgers while 
 sc_node_2 has just one forger, so it can evaluated the time taken by vrfProofCheckAgainstStake that it is executed for 
 each forger.
For the stakeTotal, grep in the test log file (sc_test.log) "Checkpoint, time and gas". The first value is the epoch 
number, the second one is the time taken for executing the stakeTotal and the third one is the used gas.
  
Configuration: 
    - 2 SC nodes connected with each other
    - 1 MC node

Test:
    - Reach fork point 1.3 and execute upgrade 
    - Reach fork point 1.4 and execute activate 
    - Create 100 forgers, skip to epochs and try to forge blocks on both nodes
    - Creates 1000 stakes in 1000 different epochs (so creating 1000 checkpoints) just for genesis forger. Execute
    stakeTotal with 100 epochs, using as a starting epoch each and every epoch where the stakes were created.

"""


class SCEvmForgerV2Perf(AccountChainSetup):
    def __init__(self):
        super().__init__(number_of_sidechain_nodes=2, forward_amount=222,
                         block_timestamp_rewind=1500 * EVM_APP_SLOT_TIME * 1500)

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

        ft_amount_in_zen = Decimal('2000.0')

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

        # Reach fork point 1.4
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

        # register 100 new forgers, 50 on node1 and 50 on node2

        reward_share = 123
        reward_address = add_0x_prefix(evm_address_sc_node_2)
        MIN_STAKED_AMOUNT_IN_ZEN = 10
        staked_amount = convertZenToZennies(MIN_STAKED_AMOUNT_IN_ZEN)

        mc_node.generate(1)

        num_of_forgers = 100  # This is the total number of forgers including the one in the genesis block
        for i in range(0, num_of_forgers - 2):
            # Create forger keys on node 1
            block_sign_pub_key_1 = sc_node_1.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
            vrf_pub_key_1 = sc_node_1.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]
            ac_registerForger(sc_node_1, block_sign_pub_key_1, vrf_pub_key_1, staked_amount,
                              reward_share=reward_share,
                              reward_address=reward_address, nonce=None)

            self.sc_sync_all()
            generate_next_block(sc_node_1, "first node")
            mc_node.generate(1)
            self.sc_sync_all()

        # Create the remaining forger on node 2
        block_sign_pub_key_2 = sc_node_2.wallet_createPrivateKey25519()["result"]["proposition"]["publicKey"]
        vrf_pub_key_2 = sc_node_2.wallet_createVrfSecret()["result"]["proposition"]["publicKey"]

        ac_registerForger(sc_node_2, block_sign_pub_key_2, vrf_pub_key_2, convertZenToZennies(100),
                          reward_share=reward_share,
                          reward_address=reward_address, nonce=None)
        self.sc_sync_all()
        generate_next_block(sc_node_1, "first node")
        self.sc_sync_all()

        forger_stake_list = sc_node_1.transaction_allForgingStakes()["result"]['stakes']
        assert_equal(num_of_forgers, len(forger_stake_list))

        mc_node.generate(1)

        # Switch 2 epochs so the created forgers are selected for the Lottery
        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
        # Try to forge blocks on node 1 and node 2, to measure the lottery time on the 2 nodes
        current_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"]
        logging.info("Check lottery time after 2 epochs after creating all the forgers: Current epoch is {}".format(
            current_epoch))
        generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=False)
        generate_next_block(sc_node_2, "second node", force_switch_to_next_epoch=False)
        mc_node.generate(1)

        # Create several checkpoints for genesis forger and check time/gas for stakeTotal
        num_of_checkpoints = 1000
        logging.info("Testing stakeTotal with number of checkpoints {}".format(num_of_checkpoints))

        delegate_method = 'delegate(bytes32,bytes32,bytes1)'
        vrf_pub_key_to_bytes = hex_str_to_bytes(vrf_pub_key_genesis)
        sign_key_to_bytes = hex_str_to_bytes(block_sign_pub_key_genesis)
        staked_amount = convertZenniesToWei(1)

        starting_epoch = sc_node_1.block_forgingInfo()["result"]["bestBlockEpochNumber"] + 1

        for i in range(0, num_of_checkpoints):
            contract_function_call(sc_node_1, forger_v2_native_contract,
                                   FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                   evm_address_sc_node_1, delegate_method, sign_key_to_bytes,
                                   vrf_pub_key_to_bytes[0:32], vrf_pub_key_to_bytes[32:],
                                   value=staked_amount, overrideGas=200000)

            generate_next_block(sc_node_1, "first node", force_switch_to_next_epoch=True)
            mc_node.generate(1)

        method = "stakeTotal(bytes32,bytes32,bytes1,address,uint32,uint32)"

        num_of_epochs = 100
        for i in range(0, num_of_checkpoints):
            from_epoch = starting_epoch + i
            start = time.time()
            contract_function_static_call(sc_node_1, forger_v2_native_contract,
                                          FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                          evm_address_sc_node_2, method, sign_key_to_bytes,
                                          vrf_pub_key_to_bytes[0:32], vrf_pub_key_to_bytes[32:],
                                          evm_address_sc_node_1,
                                          from_epoch, num_of_epochs)
            end = time.time()
            estimated_gas = forger_v2_native_contract.estimate_gas(sc_node_1, method, sign_key_to_bytes,
                                                                   vrf_pub_key_to_bytes[0:32],
                                                                   vrf_pub_key_to_bytes[32:], evm_address_sc_node_1,
                                                                   from_epoch, num_of_epochs,
                                                                   fromAddress=evm_address_sc_node_2,
                                                                   toAddress=FORGER_STAKE_V2_SMART_CONTRACT_ADDRESS,
                                                                   tag="latest")
            logging.info("Checkpoint, time and gas: {0}, {1}, {2}".format(from_epoch, end - start, estimated_gas))


if __name__ == "__main__":
    SCEvmForgerV2Perf().main()
