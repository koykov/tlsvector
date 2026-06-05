# TLS vector

TLS parser and fingerprint generation library. Provides details of TLS packets and extensions.
Supports two types of packets:
* Client Hello
* Server Hello

Also, may calculate `JA3`/`JA4` fingerprints of these packets.

## Usage

```go
package main

import "github.com/koykov/tlsvector"

var exampleClientHello = []byte{0x16, 0x03, 0x01, 0x06, ... 0xaa, 0x00, 0x01, 0x00}

func main() {
    vec := tlsvector.Acquire()
    defer tlsvector.Release(vec)
    _ = vec.Parse(exampleClientHello)
    println("full description:\n", vec.String)
    println("version: ", vec.Version())
    println("JA3: ", string(vec.JA3()))
    println("JA3_r: ", string(vec.JA3String()))
    println("JA4: ", string(vec.JA4()))
    println("JA4_r: ", string(vec.JA4String()))
}

// Output:
full description:
Record:
	Type: HANDSHAKE (22)
	Legacy version: TLS1.0 (0x0301)
	Length: 1784
Handshake:
	Type: CLIENT_HELLO (0x01)
	Length: 1780
	Version: TLS1.3 (0x0304)
	Random: 785E644FD0DC4D2C0781B0B9324311D141F9EB1D6E02AA5C170047EB03842ECA
	Session ID Length: 32
	Session ID: 63537993B885ECDAD93B837AAEDD561666754BC46837E7FDC6E70BF957CD38DD
	Cipher Suites:
		Reserved (0x7A7A)
		TLS_AES_128_GCM_SHA256 (0x1301)
		...
		TLS_RSA_WITH_AES_256_CBC_SHA (0x35)
	Compression Method Length: 1
	Compression Method: NULL (0)
	Extensions:
		ec_point_formats (0x000B):
			uncompressed (0x00) 
		supported_groups (renamed from "elliptic_curves") (0x000A):
			Reserved (0xbaba) 
			X25519MLKEM768 (0x11ec) 
			x25519 (0x001d) 
			secp256r1 (0x0017) 
			secp384r1 (0x0018) 
        ...
		application_layer_protocol_negotiation (0x0010):
			h2
			http/1.1

version: TLS1.3

JA3: d68b9314066c879bf188950f16935411
JA3_r: 771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,5-23-11-13-18-65037-51-10-45-65281-0-43-35-27-16-17613,4588-29-23-24,0

JA4: t13d1516h2_8daaf6152771_d8a2da3f94cd
JA4_r: t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014,c02b,c02c,c02f,c030,cca8,cca9_0005,000a,000b,000d,0012,0017,001b,0023,002b,002d,0033,44cd,fe0d,ff01_0403,0804,0401,0503,0805,0501,0806,0601
```

For Server Hello packet, generates `JA3s` and `JA4s` hashes on calling `JA3`/`JA4` methods.
