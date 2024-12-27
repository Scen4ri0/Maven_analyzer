rule ObfuscatedCode {
    meta:
        description = "Detects potential obfuscated or packed Java code"
        author = "Scen4ri0"
        date = "2024-12-27"
        category = "Obfuscation"

    strings:
        $short_class = /^[a-zA-Z]{1,2}\.[a-zA-Z]{1,2}$/ wide
        $garbage_code = "/* Decompiled with Procyon */"
        $random_chars = /[a-zA-Z0-9\/+=]{50,}/
        $proguard = "proguard"
        $suspicious_method_name = /^[a-zA-Z]{1,2}[0-9]{3,}$/ wide
        $encrypted_resource = /^META-INF\/[a-z0-9]{20,}\.(dat|bin|enc)$/ wide

    condition:
        (
            ($short_class or $suspicious_method_name or $garbage_code or $random_chars or $encrypted_resource)
            and not $proguard
        )
}
