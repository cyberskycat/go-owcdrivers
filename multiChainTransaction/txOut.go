package multiChainTransaction

import (
	"errors"
	"github.com/shopspring/decimal"
	"strings"
)

type TxOut struct {
	amount     []byte
	lockScript []byte
}

func newTxOutForEmptyTrans(vout []Vout, addressPrefix AddressPrefix) ([]TxOut, error) {
	if vout == nil || len(vout) == 0 {
		return nil, errors.New("No address to send when create an empty transaction!")
	}
	var ret []TxOut
	var prefixStr string
	var p2pkhPrefixByte []byte
	var p2wpkhPrefixByte []byte
	var p2shPrefixBytes []byte
	prefixStr = addressPrefix.Bech32Prefix
	p2pkhPrefixByte = addressPrefix.P2PKHPrefix
	p2wpkhPrefixByte = addressPrefix.P2WPKHPrefix
	p2shPrefixBytes = addressPrefix.P2SHPrefix

	for _, v := range vout {
		amount := uint64ToLittleEndianBytes(v.Amount)

		if strings.Index(v.Address, prefixStr) == 0 {
			redeem, err := Bech32Decode(v.Address)
			if err != nil {
				return nil, errors.New("Invalid bech32 type address!")
			}

			redeem = append([]byte{byte(len(redeem))}, redeem...)
			redeem = append([]byte{0x00}, redeem...)

			ret = append(ret, TxOut{amount, redeem})

			continue
		}

		prefix, hash, err := DecodeCheck(v.Address)
		if err != nil {
			return nil, errors.New("Invalid address to send!")
		}

		if len(hash) != 0x14 {
			return nil, errors.New("Invalid address to send!")
		}

		hash = append([]byte{byte(len(hash))}, hash...)
		hash = append([]byte{OpCodeHash160}, hash...)
		if byteArrayCompare(prefix, p2pkhPrefixByte) {
			hash = append(hash, OpCodeEqualVerify, OpCodeCheckSig)
			hash = append([]byte{OpCodeDup}, hash...)

			//如果是资产输出 生产对应的metadata
			if v.Assets.Assetref !="" {
				//process data
				//meta length of meta data
				hash = append(hash, byte(0x1c))
				//meta data part
				//meta data part 1 : (add  spkq prefix don't now why spkq)
				hash = append(hash, []byte{0x73, 0x70, 0x6b, 0x71}...)
				//meta data part 2 : (first 16 bytes of issuance txid reversed)
				txid_reversed_first_16, _ := reverseHexToBytes(v.Assets.Issuetxid[0:32])
				hash = append(hash, txid_reversed_first_16...)
				//meta data part 3 : (first output: metadata: MultiChain asset quantity  Little endian)
				qtydecimal, _ := decimal.NewFromString(v.Assets.Rawqty)
				qtyAmount := uint64(qtydecimal.IntPart())
				hash = append(hash, uint64ToLittleEndianBytes(qtyAmount)...)

				//OP_DROP
				hash = append(hash, OpCodeDrop)
			}

		} else if byteArrayCompare(prefix, p2wpkhPrefixByte) || byteArrayCompare(prefix, p2shPrefixBytes) {
			hash = append(hash, OpCodeEqual)
		} else {
			return nil, errors.New("Invalid address to send!")
		}

		ret = append(ret, TxOut{amount, hash})
	}
	return ret, nil
}

func (out TxOut) toBytes() ([]byte, error) {
	if out.amount == nil || len(out.amount) != 8 {
		return nil, errors.New("Invalid amount for a transaction output!")
	}
	if out.lockScript == nil || len(out.lockScript) == 0 {
		return nil, errors.New("Invalid lock script for a transaction output!")
	}

	ret := []byte{}
	ret = append(ret, out.amount...)
	ret = append(ret, byte(len(out.lockScript)))
	ret = append(ret, out.lockScript...)

	return ret, nil
}
