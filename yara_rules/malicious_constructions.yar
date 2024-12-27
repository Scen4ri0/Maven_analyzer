rule MaliciousEncryptionUsage {
    meta:
        description = "Detects potential misuse of encryption for malicious purposes"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "Behavioral"

    strings:
        $aes = "javax.crypto.Cipher.getInstance(\"AES\")"
        $rsa = "javax.crypto.Cipher.getInstance(\"RSA\")"
        $xor = { 33 ?? }  
        $base64_encode = "java.util.Base64.getEncoder().encodeToString"
        $base64_decode = "java.util.Base64.getDecoder().decode"

    condition:
        any of ($aes, $rsa, $xor, $base64_encode, $base64_decode)
}
