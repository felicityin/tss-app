package tss_sdk_test

import (
	"testing"
	"tss_sdk"
)

func Test_RemoveKeygenParty(t *testing.T) {
	tss_sdk.RemoveKeygenParty("1")
}
