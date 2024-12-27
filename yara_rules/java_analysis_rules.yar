include "suspicious_behavior.yar"
include "malicious_constructions.yar"
include "file_operations.yar"
include "obfuscation.yar"
include "hidden_execution.yar"
include "classloader_modification.yar"
include "strange_resources.yar"

rule ComprehensiveJavaAnalysis {
    meta:
        description = "Comprehensive analysis of Java artifacts for malicious indicators"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "Comprehensive"

    condition:
        true
}
