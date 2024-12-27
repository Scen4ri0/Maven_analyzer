rule SuspiciousBehavior_ExecAndReflection {
    meta:
        description = "Detects suspicious use of Runtime.exec and reflection"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "Behavioral"

    strings:
        $exec = "java.lang.Runtime.getRuntime().exec"
        $reflection1 = "java.lang.reflect.Method.invoke"
        $reflection2 = "java.lang.reflect.Constructor.newInstance"
        $reflection3 = "Class.forName"
        $reflection4 = "getDeclaredMethod"

    condition:
        any of ($exec, $reflection1, $reflection2, $reflection3, $reflection4)
}
