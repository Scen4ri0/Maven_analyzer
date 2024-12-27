rule ClassLoaderModification {
    meta:
        description = "Detects suspicious modifications or misuse of Java ClassLoader"
        author = "Scen4ri0"
        date = "2024-12-27"
        category = "ClassLoader"

    strings:
        $classloader = "java.lang.ClassLoader.defineClass"
        $url_loader = "java.net.URLClassLoader"
        $load_class = "Class.forName"
        $dynamic = "java.lang.invoke.MethodHandles"
        $temp_path = "/tmp/"

    condition:
        (any of ($classloader, $load_class) and $temp_path) or
        (any of ($url_loader, $dynamic))
}
