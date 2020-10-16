# one-time-password

## Provides the following features
- Generate `otpauth` URI
- HMAC-based One-time Password (HOTP) ([RFC4226](https://tools.ietf.org/html/rfc4226))
- Time-based One-time Password (TOTP) ([RFC6238](https://tools.ietf.org/html/rfc6238))
- Generate recovery codes

## Usage
### Generate `otpauth` URI
simple use case
```go
func main() {
    issuer := "istsh_company"
    accountName := "istsh@example.com"
    host := otpauth.HostTOTP

    oa, err := otpauth.GenerateOtpAuth(issuer, accountName, host)
    if err != nil {
        panic(err)
    }

    fmt.Println(oa.URL())
}

// otpauth://hotp/istsh_company:istsh@example.com?algorithm=SHA1&digits=6&issuer=istsh_company&period=30&secret=RGUIO25EXLPPMEBDHND67342HNY6UJRD
```

### HMAC-based One-time Password (HOTP)
simple use case
```go
func main() {
    secret := "RGUIO25EXLPPMEBDHND67342HNY6UJRD"
    counter := 1

    otp, err := hotp.GeneratePasscode(secret, counter)
    if err != nil {
        panic(err)
    }
    
    fmt.Println(otp)
}

// 728019
```

### Time-based One-time Password (TOTP)
simple use case
```go
func main() {
    passcode := "123456"
    secret := "RGUIO25EXLPPMEBDHND67342HNY6UJRD"
    now := time.Now()

    ok, err := totp.Validate(passcode, secret, now)
    if err != nil {
        panic(err)
    }

    fmt.Println(ok)
}

// false
```

### Generate recovery codes
simple use case
```go
func main() {
    codes, err := recovery.GenerateRecoveryCodes()
    if err != nil {
        panic(err)
    }

    for _, code := range codes {
        fmt.Println(code)
    }
}

// zFXfrWdZ
// djyHvDve
// hxGRMHtt
// cPv0C0WR
```

## License
[MIT](https://github.com/istsh/one-time-password/blob/main/LICENSE)
