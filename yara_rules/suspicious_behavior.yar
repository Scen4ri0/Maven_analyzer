rule SuspiciousBehavior_ExecAndReflection {
    meta:
        description = "Detects potentially malicious use of Runtime.exec and reflection"
        author = "Scen4ri0"
        date = "2024-12-27"
        category = "Behavioral"

    strings:
        // Вызовы Runtime.exec с подозрительными командами
        $exec = "java.lang.Runtime.getRuntime().exec"
        $suspicious_command1 = "rm -rf"
        $suspicious_command2 = "wget "
        $suspicious_command3 = "curl "

        // Подозрительное использование рефлексии
        $reflection1 = "java.lang.reflect.Method.invoke"
        $reflection2 = "java.lang.reflect.Constructor.newInstance"
        $reflection3 = "Class.forName"
        $reflection4 = "getDeclaredMethod"

        // Попытка манипуляции с приватными методами
        $private_access = "setAccessible(true)"

    condition:
        (
            $exec and any of ($suspicious_command1, $suspicious_command2, $suspicious_command3)
        ) or (
            any of ($reflection1, $reflection2, $reflection3, $reflection4)
            and $private_access
        )
}
