rule StrangeResourcesAndManifest {
    meta:
        description = "Detects unusual files or attributes in META-INF indicating potential misuse"
        author = "Scen4ri0"
        date = "2024-12-27"
        category = "Resources"

    strings:
        $suspicious_manifest1 = "Permissions: " // Исключая легитимные права доступа
        $suspicious_manifest2 = /^Class-Path: .{1,50}\.jar$/ wide // Ограничение на длину пути
        $encrypted_file = /\.enc|\.dat$/
        $hidden_file = /^META-INF\/[^\/]+\.(dat|bin|key)$/ wide
        $unknown_file = /^META-INF\/[a-zA-Z0-9_-]{10,30}\.[a-zA-Z0-9]{2,4}$/ wide
        $nested_encrypted = /META-INF\/subdir\/.{1,30}\.enc$/ // Ограничение на длину имени файла

    condition:
        (
            ($suspicious_manifest1 or $suspicious_manifest2 or $encrypted_file or $hidden_file or $nested_encrypted)
        ) or $unknown_file
}
