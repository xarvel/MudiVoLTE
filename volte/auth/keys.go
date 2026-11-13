package auth

import "fmt"

// IntegrityKey derives the ESP authentication key from IK_IM (TS 33.203 §6.1, Annex I):
// hmac-md5-96 uses IK as is; hmac-sha-1-96 appends 32 zero bits.
func IntegrityKey(alg string, ik []byte) ([]byte, error) {
	if len(ik) != 16 {
		return nil, fmt.Errorf("IK is %d bytes, want 16", len(ik))
	}
	switch alg {
	case "hmac-md5-96":
		return append([]byte(nil), ik...), nil
	case "hmac-sha-1-96":
		return append(append([]byte(nil), ik...), 0, 0, 0, 0), nil
	}
	return nil, fmt.Errorf("unsupported integrity algorithm %q", alg)
}

// EncryptionKey derives the ESP encryption key from CK_IM (TS 33.203 §6.1, Annex I).
// null returns a nil key; des-ede3-cbc is CK1 ‖ CK2 ‖ CK1 for CK = CK1 ‖ CK2.
func EncryptionKey(ealg string, ck []byte) ([]byte, error) {
	if len(ck) != 16 {
		return nil, fmt.Errorf("CK is %d bytes, want 16", len(ck))
	}
	switch ealg {
	case "", "null":
		return nil, nil
	case "aes-cbc":
		return append([]byte(nil), ck...), nil
	case "des-ede3-cbc":
		k := make([]byte, 0, 24)
		k = append(k, ck[:8]...)
		k = append(k, ck[8:]...)
		return append(k, ck[:8]...), nil
	}
	return nil, fmt.Errorf("unsupported encryption algorithm %q", ealg)
}
