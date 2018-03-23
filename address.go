package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"math/big"
	"encoding/binary"
	"fmt"
	"strconv"
)

func Sign(privKey ecdsa.PrivateKey, data string) string {
	rawData := []byte(data)
	r, s, err := ecdsa.Sign(rand.Reader, &privKey, rawData)
	if err != nil {
		log.Panic(err)
	}
	signature := append(r.Bytes(), s.Bytes()...)
	encSign := string(Base58Encode(signature))
	return encSign
}

func Verify(pubKey string, data string, signature string) bool {
	rawPubKey := Base58Decode([]byte(pubKey))
	rawSign := Base58Decode([]byte(signature))

	r := big.Int{}
	s := big.Int{}
	sigLen := len(rawSign)
	r.SetBytes(rawSign[:(sigLen / 2)])
	s.SetBytes(rawSign[(sigLen / 2):])

	x := big.Int{}
	y := big.Int{}
	keyLen := len(rawPubKey)
	x.SetBytes(rawPubKey[:(keyLen / 2)])
	y.SetBytes(rawPubKey[(keyLen / 2):])

	curve := elliptic.P256()
	realPubKey := ecdsa.PublicKey{Curve: curve, X: &x, Y: &y}
	if ecdsa.Verify(&realPubKey, []byte(data), &r, &s) == false {
		return false
	} else {
		return true
	}
}

func randomInt() uint32 {
	c := 4
	b := make([]byte, c)
	_, err := rand.Read(b)
	if err != nil {
		fmt.Println("error:", err)
		return 0
	}
	result := binary.LittleEndian.Uint32(b)
	return result
}

var RootAddress = "1HXkYSfJTQcRdLxmQBQ8KPqNR1SrQafV3r"
var DestAddress = "1BxfTe5Cx82Gr9XrCzh9JMFPYe8AU5SCLd"

func ExampleCommand() {
	ws, err := NewWallets("root")
	if err != nil {
		fmt.Println("error: ", err)
	}

	rootWallet := ws.GetWallet(RootAddress)
	rootPubKey := string(Base58Encode(rootWallet.PublicKey))
	destWallet := ws.GetWallet(DestAddress)
	destPubKey := string(Base58Encode(destWallet.PublicKey))
	data := rootPubKey
	data += destPubKey
	amount := 10000
	data += strconv.Itoa(amount)
	ri := randomInt()
	data += strconv.FormatUint(uint64(ri), 10)
	signStr := Sign(rootWallet.PrivateKey, data)

	command := fmt.Sprintf("pay %s %s %d %d %s", rootPubKey, destPubKey, amount, ri, signStr)
	fmt.Println(command)
	result := verifyTransaction(rootPubKey, destPubKey, strconv.Itoa(amount), strconv.FormatUint(uint64(ri), 10), signStr)
	fmt.Printf("result : %v\n", result)
}

func verifyTransaction(from string, to string, amount string, ri string, sign string) bool {
	data := from + to + amount + ri
	result := Verify(from, data, sign)
	return result
}

/*
func main() {
	ExampleCommand()
}
*/