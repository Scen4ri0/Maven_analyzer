rule StrangeResourcesAndManifest {
    meta:
        description = "Detects unusual files or attributes in META-INF"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "Resources"

    strings:
        $suspicious_manifest1 = "Permissions: "
        $suspicious_manifest2 = "Class-Path: "
        $encrypted_file = /.enc|\.dat/
        $hidden_file = /^META-INF\/[^\/]+$/

    condition:
        any of ($suspicious_manifest1, $suspicious_manifest2, $encrypted_file, $hidden_file)
}
