package tx

import (
	"encoding/hex"
	"testing"

	"bitbucket.org/simon_ordish/cryptolib"
)

func toSatoshi(amount float64) uint64 {
	return uint64(amount * 1e+08)
}

/*
I have read that the TXID of a bitcoin transaction is the double sha256 of the hex of a transaction with 4 bytes (0x01000000 added = SIGHASH_ALL).
However, it seems that the sigScript
of each input is ignored when performing this hash calculation.  Some articles also state that you should replace the sigScript or each input
with the scriptPubKey of the output we want to redeem.

Looking at the output of getrawtransaction, it seems that the txid is based on the entire transaction including the actual signed sigScript.

Can anyone point me in the right direction for this.
*/
// Take a real transaction and calculate it's TxID...
func TestCalcTxID2(t *testing.T) {
	hex, _ := hex.DecodeString("0200000001ab7eb14cb93b3fe7912ca748c2d3ed8fd46f8f89d07de74501a1b2e52cccf865010000006a47304402204b29409ce1fa7e3f833bcf8a6a67e263f3f0c5a266e70431063f52e751673856022009dcc5251da1cebead16771f7b31c5583df63aea948764ca80e02027b2aac1a0412102f798925328c78e8bc55ea911babbbf197ed40ae24261c79087981627e06d3d5effffffff015b4d0000000000001976a9145e9997f0cfc486fb8bb137a018ad70b1ebd8da8d88ac00000000")
	t.Logf("%x\n", cryptolib.Sha256d(hex))
}

func TestCalcTxID(t *testing.T) {
	txid, _ := hex.DecodeString("be66e10da854e7aea9338c1f91cd489768d1d6d7189f586d7a3613f2a24d5396")
	index := uint32(0)
	script, _ := hex.DecodeString("76a914dd6cce9f255a8cc17bda8ba0373df8e861cb866e88ac")
	// outscript, _ := hex.DecodeString("76a914097072524438d003d23a2f23edb65aae1bb3e46988ac")
	tx := New()

	tx.addInput(txid, index, 0, script)
	tx.addOutput(118307, "1FromKBPAS8MWsk1Yv1Yiu8rJbjfVioBHc")
	t.Logf("%x, %q\n", tx.toHex(), tx.getHash())
}

/*
01000000
01
eccf7e3034189b851985d871f91384b8ee357cd47c3024736e5676eb2debb3f2
01000000
19
76a914010966776006953d5567439e5e39f86a0d273bee88ac
ffffffff
01
605af40500000000
19
76a914d12a4a7d09c457fa6d345bd5c2348f109237db1188ac
00000000
*/
func Test(t *testing.T) {
	txid, _ := hex.DecodeString("db1fa15cb0239a0b2afa88a77e6ce8929abafd99ce5e7c6ef2225bab6500fa6f")
	index := uint32(0)
	// address : = "19dCWu1pvak7cgw5b1nFQn9LapFSQLqahC"
	amount := toSatoshi(0.00019803)
	script, _ := hex.DecodeString("76a9145e9997f0cfc486fb8bb137a018ad70b1ebd8da8d88ac")

	tx := New()

	tx.addInput(txid, index, amount, script)

	t.Logf("%+x", tx.toHex())
}

/*
0100000003c7c4e9082dfbb3713e47c1bef9f68efd9b856dfcdee318416daaa2add82770d4010000008b483045022100b2fd3f8a8c226f2addb1b663009c344e2c351dad0daf022d1cb12fe77e81563a02206e012ef6235d10ee058d4c3d61b44a8ca18ebc5e99388e6004f306b289683e02014104365c787aaf52a181a6e110f9d3daa08103f91b1512bea21398b9ea1f1beb5dae9155daad83b1dabbf316c4b6e4bb438344204a1db1d33ccb47d01c2051c0974affffffffee595b71cc5a1fb980a77af8b962534ae0049b2906fbe0790e48fa71e9f02299000000008b483045022100faf84d50e99deeef7d2cf9f8b4600b8de56fd788d9f66521a04378f90b49a87602204608cde776fda754ce871abff873dc4d29aa34c03a50d96085200e825bae73a40141045684d9b38346deb7f93b6b8282dcf8227bfcb72913d8f4c5fad9987e38770467fee26b5a0b57d0aef4df4002463ec1f1934640d6905eede1ed28bb7e432bcbd1ffffffff5e327471c5bdbecca45fccbd698a479424a31c99a9704b68e619f6b3e3b92955010000008a47304402206f361fb4b97aaea04f18cf9ff81a186e48ed4478379e6e93e0ab28d4d48226c902201565b73f2f03effacf429e7a840543c577347518f256dcc3def8558fa8effcef0141040dc0d62bd87d2e54be3f95c4187fa30d48d6cd00431978401dd798b74507d9adb457fd9434876f562735baef0bb9d6e35366c2c181b6d961b8362ad95af726aaffffffff02728b0100000000001976a914df3bd30160e6c6145baaf2c88a8844c13a00d1d588ac95871a00000000001976a9149f036f85506693bb84c5d910d58bdcf8283b20ce88ac00000000",
    "txid": "81b4c832d70cb56ff957589752eb4125a4cab78a25a8fc52d6a09e5bd4404d48",
*/
