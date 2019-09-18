package multiChainTransaction

type AddressPrefix struct {
	P2PKHPrefix  []byte
	P2WPKHPrefix []byte
	P2SHPrefix   []byte
	Bech32Prefix string
}

var (
	BTCMainnetAddressPrefix = AddressPrefix{[]byte{0x00}, []byte{0x05}, nil, "bc"}
	BTCTestnetAddressPrefix = AddressPrefix{[]byte{0x6F}, []byte{0xC4}, nil, "tb"}
	BCHMainnetAddressPrefix = AddressPrefix{[]byte{0x00}, []byte{0x05}, nil, "bc"}
	BCHTestnetAddressPrefix = AddressPrefix{[]byte{0x6F}, []byte{0xC4}, nil, "tb"}
	LTCMainnetAddressPrefix = AddressPrefix{[]byte{0x30}, []byte{0x05}, []byte{0x32}, "ltc"}
	LTCTestnetAddressPrefix = AddressPrefix{[]byte{0x6F}, []byte{0xC4}, []byte{0x3A}, "tltc"}
	ZECMainnetAddressPrefix = AddressPrefix{[]byte{0x1C, 0xB8}, []byte{0x1C, 0xBD}, nil, ""}
	ZECTestnetAddressPrefix = AddressPrefix{[]byte{0x1D, 0x25}, []byte{0x1C, 0xBA}, nil, ""}
)

const (
	DefaultTxVersion     = uint32(1)
	DefaultHashType      = uint32(1)
	MaxScriptElementSize = 520
)

const (
	SequenceFinal        = uint32(0xFFFFFFFF)
	SequenceMaxBip125RBF = uint32(0xFFFFFFFD)
)

const (
	SegWitSymbol  = byte(0)
	SegWitVersion = byte(1)
	SigHashAll    = byte(1)
)

const (
	OpCodeHash160     = byte(0xA9)
	OpCodeEqual       = byte(0x87)
	OpCodeEqualVerify = byte(0x88)
	OpCodeCheckSig    = byte(0xAC)
	OpCodeDup         = byte(0x76)
	OpCode_1          = byte(0x51)
	OpCheckMultiSig   = byte(0xAE)
	OpPushData1       = byte(0x4C)
	OpPushData2       = byte(0x4D)
	OpPushData3       = byte(0x4E)
	OpCodeDrop        = byte(0x75)
)

var (
	CurveOrder     = []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41}
	HalfCurveOrder = []byte{0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0}
)
