# Encryped Content-Encoding for HTTP

Erlang implementation of encrypted content-encoding.

https://tools.ietf.org/html/draft-thomson-http-encryption-02

This is a direct port of python code https://github.com/martinthomson/encrypted-content-encoding/blob/master/python/http_ece/__init__.py

## Usage

```erlang
    1> Salt = eece:urlsafe_decode64("mUFsKgrmI-i_-HowjX_2XA==").
    2> Key  = eece:urlsafe_decode64("F-hAEGCm7KIGUiSdS4GGtA==").
    3> Msg  = eece:urlsafe_decode64("iEPbDBuohQLznv45IlaF1eLRCeu6aWfsq-pDP7OnzgH4A0x5lyIEVAfM39RgeLekW1VgZWIFL_WvuveEhaHj0-iEvxDHw_apYGFYWEY6KmMhXgWPmFZ-2wAMnDsQ-DDVbZHsXw==").
    4> E = eece:encrypt(Msg, Key, Salt).
    5> eece:decrypt(E, Key, Salt).
```
