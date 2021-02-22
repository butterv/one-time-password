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
    issuer := "butter_company"
    accountName := "butter@example.com"
    host := otpauth.HostTOTP

    oa, err := otpauth.GenerateOtpAuth(issuer, accountName, host)
    if err != nil {
        panic(err)
    }

    fmt.Println(oa.URL())
    fmt.Println(oa.QRCode())
}

// otpauth://hotp/butter_company:butter@example.com?algorithm=SHA1&digits=6&issuer=butter_company&period=30&secret=RGUIO25EXLPPMEBDHND67342HNY6UJRD
// data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAQAAAAEAAQMAAABmvDolAAAABlBMVEX///8AAABVwtN+AAADXUlEQVR42uyZMY77LBDFn0VByQ3CRSJzLReRjJRir+UoF8E3oKRAvE8zTrLZ7iv+SyiWKsn+CmyY997M4m/9rX+9AsntBJgGRkMyBubF7CTbMMAM2G2i5Y2wTCgrE1buWf/UCfD8ujeHtXnA7CyXQCDsmXUwQDbfPNZ6gr1ucOU8dQcayOZJMsshsmAwALD3BF6ZHLeJMM3LBfhxH34ZkGt/33O5zN59vX34URefBmQdJZn4tU0sFyDDpB8i8svA7FUfrGxpJbPlLbGEnazjACG5iBPIzWf5Lk/BEkgpkG4AbPWZcWJezj7bGAi7+fw67gGAKWE5e9qKN91YN09eOwJ627He5CTlSG+iEzuxbsMAM1w8T7QRwBKaK2tDXuAzTEcAdjupiGUEZl6bz/aenJj1KAC81gbMjVjOJ+ACwNYp81EXPQCo4+jvMM3J3WMMzVmOAwS6+DjcvAQhH78U0w9I2UolxtlnWyfaGoj1nhzjPAwg2gXPAnGis77FlO191186ASFhPVKxVze2183raeIyjwQAcOSN8hSOctNUe78t6beBKTmyOVbJD6TkK9EHvqv9xwF4RtNQLupEEnImvXIophsge7uTNkqYue9Hholmf/PuEQAXtRHUIp0y1gYsJmna6QYctz1OKVtSOge6L/nw/SY/DzCrJekH0xyvN6lWvGyxCwBbX6n4OE0nO332WSMAU3L6zsztaHbEH10RAYnoBQTm9b5nuXIqFJKKHevJPfVhBECfQt6dBoldBZbRpJfa9wA0DDuSUpsnFEzp2PFzkwMAs1j2lMWJtEB4vdEVs78sqQMwyWlS44t2ptK5i5DyLcN8HAjUr7ZOKR89vnqTJIqtG5DcVz059cdyhlPH0YEQxwGmlBexJLlyiyFtnaW1f4b5TgDWCscq1lxPzkZ4x02CVhsHeFjS5Tk14ubzgm9L6gCI40izUFVIqc0OjzUO8OgBxQTzeky2U15CwnNg1QHQwb60V/CwYotGO/c9f2eYzwM6p21Opy5HbJ5VclHeB7m/DOhQXUVewl5+2CL5TKTDADuL2Txs9ZTY7MqzI+sIkDo0W8Iu+crr0Ng+/1U0AgAdeMJIWpbaXCmRx6vkdgJ0sH/og7bPh9obzfHDAH/rb/3/9V8AAAD//xCfh1DfKcM+AAAAAElFTkSuQmCC 
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
[MIT](https://github.com/butterv/one-time-password/blob/main/LICENSE)
