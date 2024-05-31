package tss_sdk

//#include <stdio.h>
//#include <stdlib.h>
//#include <string.h>
import "C"

import (
	"encoding/json"
	"strings"
	"tss_sdk/eddsacmp/keygen"
	"tss_sdk/eddsacmp/onsign"
)

type MpcExecResult struct {
	Ok           bool   `json:"ok"`
	Err          string `json:"error"`
	MsgWireBytes []byte `json:"data"`
}

type MpcResult struct {
	Ok  bool   `json:"ok"`
	Err string `json:"error"`
}

func (result MpcExecResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func (result MpcResult) ToJson() string {
	b, _ := json.Marshal(result)
	return string(b)
}

func NewKeygenLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs string,
	rootPrivKey string, // hex string
) *MpcResult {
	ids := strings.Split(pIDs, ",")
	res := keygen.NewLocalParty(key, partyIndex, partyCount, ids, rootPrivKey)
	return resFromKeygen(res)
}

func RemoveKeygenParty(key string) bool {
	return keygen.RemoveParty(key)
}

// chainCodes: hex string array
func SaveChainCodes(key string, chainCodes string) *MpcResult {
	res := keygen.SaveChainCodes(key, chainCodes)
	return resFromKeygen(res)
}

func KeygenRound1Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound1Exec(key)
	return execResFromKeygen(res)
}

func KeygenRound1Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := keygen.KeygenRound1Accept(key, from, msgWireBytes)
	return resFromKeygen(res)
}

func KeygenRound1Finish(key string) *MpcResult {
	res := keygen.KeygenRound1Finish(key)
	return resFromKeygen(res)
}

func KeygenRound2Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound2Exec(key)
	return execResFromKeygen(res)
}

func KeygenRound2Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := keygen.KeygenRound2Accept(key, from, msgWireBytes)
	return resFromKeygen(res)
}

func KeygenRound2Finish(key string) *MpcResult {
	res := keygen.KeygenRound2Finish(key)
	return resFromKeygen(res)
}

func KeygenRound3Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound3Exec(key)
	return execResFromKeygen(res)
}

func KeygenRound3Accept(key string, from int, msgWireBytes string) *MpcResult {
	res := keygen.KeygenRound3Accept(key, from, msgWireBytes)
	return resFromKeygen(res)
}

func KeygenRound3Finish(key string) *MpcResult {
	res := keygen.KeygenRound3Finish(key)
	return resFromKeygen(res)
}

// chainCodes: hex string array
func KeygenRound4Exec(key string) *MpcExecResult {
	res := keygen.KeygenRound4Exec(key)
	return execResFromKeygen(res)
}

// ---------------------onsign------------------------

func NewSignLocalParty(
	key string,
	partyIndex int,
	partyCount int,
	pIDs string,
	msg string, // hex string
	keyData string, // keygen.LocalPartySaveData, base64 string
	refreshData string, // refresh.LocalPartySaveData, base64 string
	walletPath string,
) *MpcResult {
	ids := strings.Split(pIDs, ",")
	res := onsign.NewLocalParty(key, partyIndex, partyCount, ids, msg, keyData, refreshData, walletPath)
	return resFromOnsign(res)
}

func RemoveSignParty(key string) bool {
	return onsign.RemoveSignParty(key)
}

func OnSignRound1Exec(key string) *MpcExecResult {
	res := onsign.OnSignRound1Exec(key)
	return execResFromOnsign(res)
}

func GetOnSignRound1Msg(key string, to int) *MpcExecResult {
	res := onsign.GetRound1Msg2(key, to)
	return execResFromOnsign(res)
}

func OnSignRound1MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound1MsgAccept(key, from, msgWireBytes)
	return resFromOnsign(res)
}

func OnSignRound1Finish(key string) *MpcResult {
	res := onsign.OnSignRound1Finish(key)
	return resFromOnsign(res)
}

func OnSignRound2Exec(key string) *MpcResult {
	res := onsign.OnsignRound2Exec(key)
	return resFromOnsign(res)
}

func GetOnSignRound2Msg(key string, to int) *MpcExecResult {
	res := onsign.GetRound2Msg(key, to)
	return execResFromOnsign(res)
}

func OnSignRound2MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound2MsgAccept(key, from, msgWireBytes)
	return resFromOnsign(res)
}

func OnSignRound2Finish(key string) *MpcResult {
	res := onsign.OnSignRound2Finish(key)
	return resFromOnsign(res)
}

func OnSignRound3Exec(key string) *MpcExecResult {
	res := onsign.OnsignRound3Exec(key)
	return execResFromOnsign(res)
}

func OnSignRound3MsgAccept(key string, from int, msgWireBytes string) *MpcResult {
	res := onsign.OnSignRound3MsgAccept(key, from, msgWireBytes)
	return resFromOnsign(res)
}

func OnSignRound3Finish(key string) *MpcResult {
	res := onsign.OnSignRound3Finish(key)
	return resFromOnsign(res)
}

func OnSignFinalExec(key string) *MpcExecResult {
	res := onsign.OnsignFinalExec(key)
	return execResFromOnsign(res)
}

func execResFromKeygen(res keygen.KeygenExecResult) *MpcExecResult {
	return &MpcExecResult{
		Ok:           res.Ok,
		Err:          res.Err,
		MsgWireBytes: res.MsgWireBytes,
	}
}

func resFromKeygen(res keygen.KeygenResult) *MpcResult {
	return &MpcResult{
		Ok:  res.Ok,
		Err: res.Err,
	}
}

func execResFromOnsign(res onsign.OnsignExecResult) *MpcExecResult {
	return &MpcExecResult{
		Ok:           res.Ok,
		Err:          res.Err,
		MsgWireBytes: res.MsgWireBytes,
	}
}

func resFromOnsign(res onsign.OnsignResult) *MpcResult {
	return &MpcResult{
		Ok:  res.Ok,
		Err: res.Err,
	}
}
