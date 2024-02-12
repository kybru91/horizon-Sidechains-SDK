#!/usr/bin/env python3
import logging
from decimal import Decimal

from SidechainTestFramework.account.ac_chain_setup import AccountChainSetup
from SidechainTestFramework.account.ac_utils import estimate_gas, deploy_smart_contract
from SidechainTestFramework.account.ac_use_smart_contract import SmartContract
from SidechainTestFramework.account.utils import VER_1_3_FORK_EPOCH
from SidechainTestFramework.scutil import generate_next_block, EVM_APP_SLOT_TIME
from test_framework.util import assert_equal

"""
Check the EVM estimateGas RPC method.

Configuration: bootstrap 1 SC node and start it with genesis info extracted from a mainchain node.
    - Mine some blocks to reach hard fork
    - Create 1 SC node
    - Extract genesis info
    - Start SC node with that genesis info

Test:
    For the SC node:
        - verify the MC block is included
    For estimateGas RPC method:
        - Contract Deployment
        - EOA to EOA
        - EOA to EOA with non-empty data
        - EOA to EOA without having funds
        - forging stake
        - SC to MC withdrawal
        - Forger address in access list and Shanghai activation
"""


class SCEvmEstimateGas(AccountChainSetup):

    def __init__(self):
        super().__init__(block_timestamp_rewind=1500 * EVM_APP_SLOT_TIME * VER_1_3_FORK_EPOCH, withdrawalEpochLength=10)

    def run_test(self):
        sc_node = self.sc_nodes[0]
        ft_amount_in_zen = Decimal("33.22")

        self.sc_ac_setup(ft_amount_in_zen=ft_amount_in_zen)

        # Test data was executed with one of the ethereum mainnet rpc servers from here https://chainlist.org/chain/1

        # Test contract creation with ERC20 (TestERC20.sol with additional mint function) contract bytecode
        data = '0x60806040523480156200001157600080fd5b50604051620025d2380380620025d283398181016040528101906200003791906200045d565b81818160039080519060200190620000519291906200032f565b5080600490805190602001906200006a9291906200032f565b5050506200008d62000081620000d560201b60201c565b620000dd60201b60201c565b620000cd33620000a2620001a360201b60201c565b600a620000b0919062000681565b633b9aca00620000c19190620007be565b620001ac60201b60201c565b5050620009c0565b600033905090565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905081600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b60006012905090565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614156200021f576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040162000216906200051a565b60405180910390fd5b62000233600083836200032560201b60201c565b8060026000828254620002479190620005c9565b92505081905550806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546200029e9190620005c9565b925050819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516200030591906200053c565b60405180910390a362000321600083836200032a60201b60201c565b5050565b505050565b505050565b8280546200033d906200086c565b90600052602060002090601f016020900481019282620003615760008555620003ad565b82601f106200037c57805160ff1916838001178555620003ad565b82800160010185558215620003ad579182015b82811115620003ac5782518255916020019190600101906200038f565b5b509050620003bc9190620003c0565b5090565b5b80821115620003db576000816000905550600101620003c1565b5090565b6000620003f6620003f08462000582565b62000559565b9050828152602081018484840111156200041557620004146200096a565b5b6200042284828562000836565b509392505050565b600082601f83011262000442576200044162000965565b5b815162000454848260208601620003df565b91505092915050565b6000806040838503121562000477576200047662000974565b5b600083015167ffffffffffffffff8111156200049857620004976200096f565b5b620004a6858286016200042a565b925050602083015167ffffffffffffffff811115620004ca57620004c96200096f565b5b620004d8858286016200042a565b9150509250929050565b6000620004f1601f83620005b8565b9150620004fe8262000997565b602082019050919050565b62000514816200081f565b82525050565b600060208201905081810360008301526200053581620004e2565b9050919050565b600060208201905062000553600083018462000509565b92915050565b60006200056562000578565b9050620005738282620008a2565b919050565b6000604051905090565b600067ffffffffffffffff821115620005a0576200059f62000936565b5b620005ab8262000979565b9050602081019050919050565b600082825260208201905092915050565b6000620005d6826200081f565b9150620005e3836200081f565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156200061b576200061a620008d8565b5b828201905092915050565b6000808291508390505b6001851115620006785780860481111562000650576200064f620008d8565b5b6001851615620006605780820291505b808102905062000670856200098a565b945062000630565b94509492505050565b60006200068e826200081f565b91506200069b8362000829565b9250620006ca7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8484620006d2565b905092915050565b600082620006e45760019050620007b7565b81620006f45760009050620007b7565b81600181146200070d576002811462000718576200074e565b6001915050620007b7565b60ff8411156200072d576200072c620008d8565b5b8360020a915084821115620007475762000746620008d8565b5b50620007b7565b5060208310610133831016604e8410600b8410161715620007885782820a905083811115620007825762000781620008d8565b5b620007b7565b62000797848484600162000626565b92509050818404811115620007b157620007b0620008d8565b5b81810290505b9392505050565b6000620007cb826200081f565b9150620007d8836200081f565b9250817fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0483118215151615620008145762000813620008d8565b5b828202905092915050565b6000819050919050565b600060ff82169050919050565b60005b838110156200085657808201518184015260208101905062000839565b8381111562000866576000848401525b50505050565b600060028204905060018216806200088557607f821691505b602082108114156200089c576200089b62000907565b5b50919050565b620008ad8262000979565b810181811067ffffffffffffffff82111715620008cf57620008ce62000936565b5b80604052505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600080fd5b600080fd5b600080fd5b600080fd5b6000601f19601f8301169050919050565b60008160011c9050919050565b7f45524332303a206d696e7420746f20746865207a65726f206164647265737300600082015250565b611c0280620009d06000396000f3fe608060405234801561001057600080fd5b506004361061010b5760003560e01c806370a08231116100a257806395d89b411161007157806395d89b41146102a6578063a457c2d7146102c4578063a9059cbb146102f4578063dd62ed3e14610324578063f2fde38b146103545761010b565b806370a0823114610232578063715018a61461026257806379cc67901461026c5780638da5cb5b146102885761010b565b8063313ce567116100de578063313ce567146101ac57806339509351146101ca57806340c10f19146101fa57806342966c68146102165761010b565b806306fdde0314610110578063095ea7b31461012e57806318160ddd1461015e57806323b872dd1461017c575b600080fd5b610118610370565b60405161012591906114b0565b60405180910390f35b610148600480360381019061014391906111f4565b610402565b6040516101559190611495565b60405180910390f35b610166610425565b6040516101739190611652565b60405180910390f35b610196600480360381019061019191906111a1565b61042f565b6040516101a39190611495565b60405180910390f35b6101b461045e565b6040516101c1919061166d565b60405180910390f35b6101e460048036038101906101df91906111f4565b610467565b6040516101f19190611495565b60405180910390f35b610214600480360381019061020f91906111f4565b61049e565b005b610230600480360381019061022b9190611234565b6104b4565b005b61024c60048036038101906102479190611134565b6104c8565b6040516102599190611652565b60405180910390f35b61026a610510565b005b610286600480360381019061028191906111f4565b610524565b005b610290610544565b60405161029d919061147a565b60405180910390f35b6102ae61056e565b6040516102bb91906114b0565b60405180910390f35b6102de60048036038101906102d991906111f4565b610600565b6040516102eb9190611495565b60405180910390f35b61030e600480360381019061030991906111f4565b610677565b60405161031b9190611495565b60405180910390f35b61033e60048036038101906103399190611161565b61069a565b60405161034b9190611652565b60405180910390f35b61036e60048036038101906103699190611134565b610721565b005b60606003805461037f906117b6565b80601f01602080910402602001604051908101604052809291908181526020018280546103ab906117b6565b80156103f85780601f106103cd576101008083540402835291602001916103f8565b820191906000526020600020905b8154815290600101906020018083116103db57829003601f168201915b5050505050905090565b60008061040d6107a5565b905061041a8185856107ad565b600191505092915050565b6000600254905090565b60008061043a6107a5565b9050610447858285610978565b610452858585610a04565b60019150509392505050565b60006012905090565b6000806104726107a5565b9050610493818585610484858961069a565b61048e91906116a4565b6107ad565b600191505092915050565b6104a6610c85565b6104b08282610d03565b5050565b6104c56104bf6107a5565b82610e63565b50565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b610518610c85565b610522600061103a565b565b610536826105306107a5565b83610978565b6105408282610e63565b5050565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b60606004805461057d906117b6565b80601f01602080910402602001604051908101604052809291908181526020018280546105a9906117b6565b80156105f65780601f106105cb576101008083540402835291602001916105f6565b820191906000526020600020905b8154815290600101906020018083116105d957829003601f168201915b5050505050905090565b60008061060b6107a5565b90506000610619828661069a565b90508381101561065e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161065590611612565b60405180910390fd5b61066b82868684036107ad565b60019250505092915050565b6000806106826107a5565b905061068f818585610a04565b600191505092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b610729610c85565b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff161415610799576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161079090611512565b60405180910390fd5b6107a28161103a565b50565b600033905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16141561081d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610814906115f2565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16141561088d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161088490611532565b60405180910390fd5b80600160008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b9258360405161096b9190611652565b60405180910390a3505050565b6000610984848461069a565b90507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81146109fe57818110156109f0576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109e790611552565b60405180910390fd5b6109fd84848484036107ad565b5b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff161415610a74576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a6b906115d2565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415610ae4576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610adb906114d2565b60405180910390fd5b610aef838383611100565b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905081811015610b75576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610b6c90611572565b60405180910390fd5b8181036000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550816000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254610c0891906116a4565b925050819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef84604051610c6c9190611652565b60405180910390a3610c7f848484611105565b50505050565b610c8d6107a5565b73ffffffffffffffffffffffffffffffffffffffff16610cab610544565b73ffffffffffffffffffffffffffffffffffffffff1614610d01576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610cf890611592565b60405180910390fd5b565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415610d73576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d6a90611632565b60405180910390fd5b610d7f60008383611100565b8060026000828254610d9191906116a4565b92505081905550806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000828254610de691906116a4565b925050819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051610e4b9190611652565b60405180910390a3610e5f60008383611105565b5050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff161415610ed3576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610eca906115b2565b60405180910390fd5b610edf82600083611100565b60008060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905081811015610f65576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610f5c906114f2565b60405180910390fd5b8181036000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508160026000828254610fbc91906116fa565b92505081905550600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef846040516110219190611652565b60405180910390a361103583600084611105565b505050565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905081600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b505050565b505050565b60008135905061111981611b9e565b92915050565b60008135905061112e81611bb5565b92915050565b60006020828403121561114a57611149611846565b5b60006111588482850161110a565b91505092915050565b6000806040838503121561117857611177611846565b5b60006111868582860161110a565b92505060206111978582860161110a565b9150509250929050565b6000806000606084860312156111ba576111b9611846565b5b60006111c88682870161110a565b93505060206111d98682870161110a565b92505060406111ea8682870161111f565b9150509250925092565b6000806040838503121561120b5761120a611846565b5b60006112198582860161110a565b925050602061122a8582860161111f565b9150509250929050565b60006020828403121561124a57611249611846565b5b60006112588482850161111f565b91505092915050565b61126a8161172e565b82525050565b61127981611740565b82525050565b600061128a82611688565b6112948185611693565b93506112a4818560208601611783565b6112ad8161184b565b840191505092915050565b60006112c5602383611693565b91506112d08261185c565b604082019050919050565b60006112e8602283611693565b91506112f3826118ab565b604082019050919050565b600061130b602683611693565b9150611316826118fa565b604082019050919050565b600061132e602283611693565b915061133982611949565b604082019050919050565b6000611351601d83611693565b915061135c82611998565b602082019050919050565b6000611374602683611693565b915061137f826119c1565b604082019050919050565b6000611397602083611693565b91506113a282611a10565b602082019050919050565b60006113ba602183611693565b91506113c582611a39565b604082019050919050565b60006113dd602583611693565b91506113e882611a88565b604082019050919050565b6000611400602483611693565b915061140b82611ad7565b604082019050919050565b6000611423602583611693565b915061142e82611b26565b604082019050919050565b6000611446601f83611693565b915061145182611b75565b602082019050919050565b6114658161176c565b82525050565b61147481611776565b82525050565b600060208201905061148f6000830184611261565b92915050565b60006020820190506114aa6000830184611270565b92915050565b600060208201905081810360008301526114ca818461127f565b905092915050565b600060208201905081810360008301526114eb816112b8565b9050919050565b6000602082019050818103600083015261150b816112db565b9050919050565b6000602082019050818103600083015261152b816112fe565b9050919050565b6000602082019050818103600083015261154b81611321565b9050919050565b6000602082019050818103600083015261156b81611344565b9050919050565b6000602082019050818103600083015261158b81611367565b9050919050565b600060208201905081810360008301526115ab8161138a565b9050919050565b600060208201905081810360008301526115cb816113ad565b9050919050565b600060208201905081810360008301526115eb816113d0565b9050919050565b6000602082019050818103600083015261160b816113f3565b9050919050565b6000602082019050818103600083015261162b81611416565b9050919050565b6000602082019050818103600083015261164b81611439565b9050919050565b6000602082019050611667600083018461145c565b92915050565b6000602082019050611682600083018461146b565b92915050565b600081519050919050565b600082825260208201905092915050565b60006116af8261176c565b91506116ba8361176c565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff038211156116ef576116ee6117e8565b5b828201905092915050565b60006117058261176c565b91506117108361176c565b925082821015611723576117226117e8565b5b828203905092915050565b60006117398261174c565b9050919050565b60008115159050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b600060ff82169050919050565b60005b838110156117a1578082015181840152602081019050611786565b838111156117b0576000848401525b50505050565b600060028204905060018216806117ce57607f821691505b602082108114156117e2576117e1611817565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600080fd5b6000601f19601f8301169050919050565b7f45524332303a207472616e7366657220746f20746865207a65726f206164647260008201527f6573730000000000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a206275726e20616d6f756e7420657863656564732062616c616e60008201527f6365000000000000000000000000000000000000000000000000000000000000602082015250565b7f4f776e61626c653a206e6577206f776e657220697320746865207a65726f206160008201527f6464726573730000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a20617070726f766520746f20746865207a65726f20616464726560008201527f7373000000000000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a20696e73756666696369656e7420616c6c6f77616e6365000000600082015250565b7f45524332303a207472616e7366657220616d6f756e742065786365656473206260008201527f616c616e63650000000000000000000000000000000000000000000000000000602082015250565b7f4f776e61626c653a2063616c6c6572206973206e6f7420746865206f776e6572600082015250565b7f45524332303a206275726e2066726f6d20746865207a65726f2061646472657360008201527f7300000000000000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a207472616e736665722066726f6d20746865207a65726f20616460008201527f6472657373000000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a20617070726f76652066726f6d20746865207a65726f2061646460008201527f7265737300000000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760008201527f207a65726f000000000000000000000000000000000000000000000000000000602082015250565b7f45524332303a206d696e7420746f20746865207a65726f206164647265737300600082015250565b611ba78161172e565b8114611bb257600080fd5b50565b611bbe8161176c565b8114611bc957600080fd5b5056fea264697066735822122087b660d81a0b4c64fea037a87fa782fb475cd227094a04112ee89714ca9325a364736f6c634300080700330000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'

        # result from ethereum mainnet node execution "result": "0x1a1089"
        response = estimate_gas(sc_node, self.evm_address, data=data)
        assert_equal('0x1a1089', response['result'])

        # Test EOA to EOA
        to = '0xd3CdA913deB6f67967B99D67aCDFa1712C293601'
        # result from ethereum mainnet node execution "result": "0x5208"
        response = estimate_gas(sc_node, self.evm_address, to_address=to)
        assert_equal('0x5208', response['result'])

        # Test EOA to EOA with non-empty data
        # result from ethereum mainnet node execution "result": "0x27a2c"
        response = estimate_gas(sc_node, self.evm_address, to_address=to, data=data)
        assert_equal('0x27a2c', response['result'])

        # Test EOA to EOA without having enough funds
        value = '0x100000000000000000'
        # result from ethereum mainnet node execution - Invalid params: insufficient funds for transfer
        # -32602 = Invalid params
        response = estimate_gas(sc_node, self.evm_address, to_address=to, data=data, value=value)
        logging.info(response['error'])
        assert_equal(-32602, response['error']['code'])

        # Test estimating forging stake
        # data from AccountTransactionApiRouteTest
        data = '0x5ca748ff1122334455669988112233445566778811223344556677881122334455667788aabbddddeeff0099aabbccddeeff0099aabbccddeeff0099aabbccddeeff00123400000000000000000000000000000000000000000000000000000000000000000000000000000000000000bbdf1daf64ed9d6e30f80b93f647b8bc6ea13191'
        to = '0x0000000000000000000022222222222222222222'
        value = '0xE8D4A51000'
        nonce = '0x1'
        response = estimate_gas(sc_node, self.evm_address, to_address=to, data=data, value=value, nonce=nonce)
        assert_equal('0x35f84', response['result'])

        # Test estimating forging stake with invalid value - Execution reverted
        # -32000 = Execution reverted
        # data from AccountTransactionApiRouteTest
        value = '0x1'
        response = estimate_gas(sc_node, self.evm_address, to_address=to, data=data, value=value, nonce=nonce)
        logging.info(response['error'])
        assert_equal(-32000, response['error']['code'])

        # Test estimating SC to MC withdrawal
        # data from AccountTransactionApiRouteTest
        data = '0x4267ec5edbcbaf2b14a48cfc24941ef5acfdac0a8c590255000000000000000000000000'
        to = '0x0000000000000000000011111111111111111111'
        value = '0xE8D4A51000'
        response = estimate_gas(sc_node, self.evm_address, to_address=to, data=data, value=value)
        assert_equal('0x15ef4', response['result'])

        # Check how the gas used changes, adding the forger address in the access list with Shanghai
        # (EIP-3651: Warm COINBASE).
        # In Paris, only 'from' and 'to' addresses are automatically added to the access list. Starting from Shanghai the
        # forger is added to the access list too. Any access to the state of an address in address list costs less gas
        # that the same state access of another address. This test verifies that accessing the state of the forger costs
        # the same gas as accessing the state of an address different from 'from' or 'to' in Paris, while, after Shanghai
        # activation, the cost is lesser than before and similar to the 'to' address cost.

        # Deploying smart contract qa/SidechainTestFramework/account/smart_contract_resources/contracts/AccessListTest.sol
        access_contract = SmartContract("AccessListTest")
        logging.info(access_contract)
        access_contract_address = deploy_smart_contract(sc_node, access_contract, self.evm_address)

        latest_block = sc_node.block_best()
        forger_address = latest_block['result']['block']['header']['forgerAddress']['address']

        sc_address_not_in_al = sc_node.wallet_createPrivateKeySecp256k1()["result"]["proposition"]["address"]

        # Gas costs for cold/warm access (see GasUtil.scala/StateDbAccountStateViewGasTracked.scala)
        cold_account_access_cost_eip2929 = 2600
        warm_storage_read_cost_eip2929 = 100

        gas_saved_with_access_list = cold_account_access_cost_eip2929 - warm_storage_read_cost_eip2929

        method = "getBalance(address)"
        if self.options.all_forks is False:
            estimated_gas_to_paris = access_contract.estimate_gas(sc_node, method, access_contract_address, value=0,
                                                                  fromAddress=self.evm_address,
                                                                  toAddress=access_contract_address,
                                                                  tag="latest")

            estimated_gas_forger_paris = access_contract.estimate_gas(sc_node, method, forger_address, value=0,
                                                                      fromAddress=self.evm_address,
                                                                      toAddress=access_contract_address,
                                                                      tag="latest")
            estimated_gas_address_not_in_al_paris = access_contract.estimate_gas(sc_node, method, sc_address_not_in_al,
                                                                                 value=0,
                                                                                 fromAddress=self.evm_address,
                                                                                 toAddress=access_contract_address,
                                                                                 tag="latest")

            assert_equal(estimated_gas_forger_paris, estimated_gas_address_not_in_al_paris)
            assert_equal(estimated_gas_to_paris + gas_saved_with_access_list, estimated_gas_forger_paris)

            # reach the SHANGHAI fork
            current_best_epoch = sc_node.block_forgingInfo()["result"]["bestBlockEpochNumber"]

            for i in range(0, VER_1_3_FORK_EPOCH - current_best_epoch):
                generate_next_block(sc_node, "first node", force_switch_to_next_epoch=True)
                self.sc_sync_all()

        estimated_gas_to_shanghai = access_contract.estimate_gas(sc_node, method, access_contract_address, value=0,
                                                                 fromAddress=self.evm_address,
                                                                 toAddress=access_contract_address,
                                                                 tag="latest")
        estimated_gas_forger_shanghai = access_contract.estimate_gas(sc_node, method, forger_address, value=0,
                                                                     fromAddress=self.evm_address,
                                                                     toAddress=access_contract_address,
                                                                     tag="latest")
        estimated_gas_address_not_in_al_shanghai = access_contract.estimate_gas(sc_node, method, sc_address_not_in_al,
                                                                                value=0,
                                                                                fromAddress=self.evm_address,
                                                                                toAddress=access_contract_address,
                                                                                tag="latest")

        assert_equal(estimated_gas_forger_shanghai + gas_saved_with_access_list,
                     estimated_gas_address_not_in_al_shanghai)
        assert_equal(estimated_gas_forger_shanghai, estimated_gas_to_shanghai)

if __name__ == "__main__":
    SCEvmEstimateGas().main()
