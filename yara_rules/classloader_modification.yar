rule ClassLoaderModification {
    meta:
        description = "Detects modifications or misuse of Java ClassLoader"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "ClassLoader"

    strings:
        $classloader = "java.lang.ClassLoader.defineClass"
        $url_loader = "java.net.URLClassLoader"
        $load_class = "Class.forName"
        $dynamic = "java.lang.invoke.MethodHandles"

    condition:
        any of ($classloader, $url_loader, $load_class, $dynamic)
}
