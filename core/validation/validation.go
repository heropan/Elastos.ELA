package validation

import (
	"errors"

	"Elastos.ELA/crypto"
	. "Elastos.ELA/core/signature"
	"Elastos.ELA/vm"
	"Elastos.ELA/vm/interfaces"
	"Elastos.ELA/core/transaction"
)


func VerifySignature(txn *transaction.Transaction) (bool, error) {
	hashes, err := txn.GetProgramHashes()
	if err != nil {
		return false, err
	}

	programs := txn.GetPrograms()
	Length := len(hashes)
	if Length != len(programs) {
		return false, errors.New("The number of data hashes is different with number of programs.")
	}

	programs = txn.GetPrograms()

	for i := 0; i < len(programs); i++ {

		code := programs[i].Code
		param := programs[i].Parameter

		programHash, err := ToProgramHash(code)
		if err != nil {
			return false, err
		}

		if hashes[i] != programHash {
			return false, errors.New("The data hashes is different with corresponding program code.")
		}
		// Get transaction type
		signType, err := txn.GetTransactionType()
		if err != nil {
			return false, err
		}
		if signType == STANDARD {
			// Remove length byte and sign type byte
			publicKeyBytes := code[1:len(code)-1]
			content := txn.GetDataContent()
			// Remove length byte
			signature := param[1:]

			return checkStandardSignature(publicKeyBytes, content, signature)

		} else if signType == MULTISIG {
			publicKeys, err := txn.GetMultiSignPublicKeys()
			if err != nil {
				return false, err
			}
			return checkMultiSignSignatures(code, param, txn.GetDataContent(), publicKeys)

		} else if signType == SCRIPT {
			programCode := code[0:len(code)-1]
			var cryptos interfaces.ICrypto
			cryptos = new(vm.ECDsaCrypto)
			se := vm.NewExecutionEngine(txn, cryptos, 1200, nil, nil)
			se.LoadScript(programCode, false)
			se.LoadScript(programs[i].Parameter, true)
			se.Execute()

			if se.GetState() != vm.HALT {
				return false, errors.New("[VM] Finish State not equal to HALT.")
			}

			if se.GetEvaluationStack().Count() != 1 {
				return false, errors.New("[VM] Execute Engine Stack Count Error.")
			}

			if flag := se.GetExecuteResult(); !flag {
				return false, errors.New("[VM] Check Sig FALSE.")
			}
		} else {
			return false, errors.New("unknown signature type")
		}
	}

	return true, nil
}

func checkStandardSignature(publicKeyBytes, content, signature []byte) (bool, error) {
	publicKey, err := crypto.DecodePoint(publicKeyBytes)
	if err != nil {
		return false, err
	}
	err = crypto.Verify(*publicKey, content, signature)
	if err == nil {
		return false, err
	}
	return true, nil
}

func checkMultiSignSignatures(code, param, content []byte, publicKeys [][]byte) (bool, error) {
	// Get N parameter
	n := int(code[len(code)-2]) - PUSH1 + 1
	// Get M parameter
	m := int(code[0]) - PUSH1 + 1
	if m < 1 || m > n {
		return false, errors.New("invalid multi sign script code")
	}
	if len(publicKeys) != n {
		return false, errors.New("invalitransactiond multi sign public key script count")
	}

	signatureCount := 0
	for i := 0; i < len(param); i += SignatureScriptLength {
		// Remove length byte
		sign := param[i:i+SignatureScriptLength][1:]
		// Get signature index, if signature exists index will not be -1
		index := -1
		for i, publicKey := range publicKeys {
			pubKey, err := crypto.DecodePoint(publicKey[1:])
			if err != nil {
				return false, err
			}
			err = crypto.Verify(*pubKey, content, sign)
			if err == nil {
				index = i
			}
		}
		if index != -1 {
			signatureCount++
		}
	}
	// Check signature count
	if signatureCount != m {
		return false, errors.New("invalid signature count")
	}

	return true, nil
}