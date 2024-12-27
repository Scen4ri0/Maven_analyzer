rule FileOperations {
    meta:
        description = "Detects suspicious file operations such as deletion or overwriting"
        author = "Scen4ri0"
        date = "2024-12-27"
        category = "File I/O"

    strings:
        $file_delete = "File.delete()"
        $file_write = "FileOutputStream.write"
        $temp_dir = "/tmp/"
        $meta_inf = "META-INF/"
        $suspicious_log = "deleteLogs()"
        $log_delete = "log.txt"

    condition:
        (
            $file_delete and ($temp_dir or $meta_inf) and not $log_delete
        ) or
        (
            $file_write and ($temp_dir or $meta_inf)
        ) or
        $suspicious_log
}
