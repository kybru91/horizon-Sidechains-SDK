package lib

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	gethTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"libevm/lib/runtime"
	"libevm/types"
	"math/rand"
	"time"
)

type EvmParams struct {
	HandleParams
	Config  types.SerializableConfig `json:"config"`
	Address *common.Address          `json:"address"`
	Input   []byte                   `json:"input"`
	Nonce   uint64                   `json:"nonce"`
}

type EvmResult struct {
	ReturnData  []byte          `json:"returnData"`
	Address     *common.Address `json:"address"`
	LeftOverGas uint64          `json:"leftOverGas"`
	EvmError    string          `json:"evmError"`
}

type EvmApplyResult struct {
	UsedGas         uint64           `json:"usedGas"`
	EvmError        string           `json:"evmError"`
	ReturnData      []byte           `json:"returnData"`
	ContractAddress *common.Address  `json:"contractAddress"`
	Logs            []*gethTypes.Log `json:"logs"`
}

func (s *Service) EvmExecute(params EvmParams) (error, *EvmResult) {
	err, statedb := s.getState(params.Handle)
	if err != nil {
		return err, nil
	}
	cfg := params.Config.GetConfig()
	cfg.State = statedb
	var (
		result = &EvmResult{}
		evmErr error
	)
	if params.Address == nil {
		var contractAddress common.Address
		_, contractAddress, result.LeftOverGas, evmErr = runtime.Create(params.Input, cfg)
		result.Address = &contractAddress
	} else {
		result.ReturnData, result.LeftOverGas, evmErr = runtime.Call(*params.Address, params.Input, cfg)
	}
	if evmErr != nil {
		result.EvmError = evmErr.Error()
	}
	return nil, result
}

func (s *Service) EvmApply(params EvmParams) (error, *EvmApplyResult) {
	err, statedb := s.getState(params.Handle)
	if err != nil {
		return err, nil
	}
	cfg := params.Config.GetConfig()
	runtime.SetDefaults(cfg)

	// TODO: this mocks the tx hash with random, replace with real tx hash
	randSource := rand.NewSource(time.Now().UnixNano())
	randGenerator := rand.New(randSource)
	txHashRand := make([]byte, common.HashLength)
	randGenerator.Read(txHashRand)

	var (
		txHash         = common.BytesToHash(txHashRand)
		txIndexInBlock = 0
		blockContext   = vm.BlockContext{
			CanTransfer: core.CanTransfer,
			Transfer:    core.Transfer,
			GetHash:     cfg.GetHashFn,
			Coinbase:    cfg.Coinbase,
			BlockNumber: cfg.BlockNumber,
			Time:        cfg.Time,
			Difficulty:  cfg.Difficulty,
			GasLimit:    cfg.GasLimit,
			BaseFee:     cfg.BaseFee,
		}
		msg       = gethTypes.NewMessage(cfg.Origin, params.Address, params.Nonce, cfg.Value, cfg.GasLimit, cfg.GasPrice, cfg.GasPrice, cfg.GasPrice, params.Input, nil, false)
		txContext = core.NewEVMTxContext(msg)
		evm       = vm.NewEVM(blockContext, txContext, statedb, cfg.ChainConfig, cfg.EVMConfig)
	)

	gasPool := new(core.GasPool).AddGas(msg.Gas())
	statedb.Prepare(txHash, txIndexInBlock)

	// reference for the following is:
	// https://github.com/ethereum/go-ethereum/blob/5bc4e8f09d7c9369b718b16c1c073070ee758395/core/state_processor.go#L95
	// the actual receipt is expected to be created in the core

	// Apply the transaction to the current state (included in the env).
	result, err := core.ApplyMessage(evm, msg, gasPool)
	if err != nil {
		return err, nil
	}

	// Update the state with pending changes.
	statedb.Finalise(true)

	applyResult := &EvmApplyResult{
		UsedGas: result.UsedGas,
		Logs:    statedb.GetLogs(txHash, common.Hash{}),
	}

	// no error means successful transaction, otherwise failure
	if result.Err != nil {
		applyResult.EvmError = result.Err.Error()
	}

	// If the transaction created a contract, store the creation address in the receipt.
	if msg.To() == nil {
		contractAddress := crypto.CreateAddress(evm.TxContext.Origin, msg.Nonce())
		applyResult.ContractAddress = &contractAddress
	} else {
		applyResult.ReturnData = result.ReturnData
	}

	return nil, applyResult
}
