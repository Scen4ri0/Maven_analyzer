rule ObfuscatedCode {
    meta:
        description = "Detects potential obfuscated or packed Java code"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "Obfuscation"

    strings:
        $short_class = /^[a-zA-Z]{1,3}\.[a-zA-Z]{1,3}$/ wide
        $garbage_code = "/* Decompiled with Procyon */"
        $random_chars = /[a-zA-Z0-9\/+=]{30,}/
        $proguard = "proguard"

    condition:
        any of ($short_class, $garbage_code, $random_chars, $proguard)
}
