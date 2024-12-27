rule FileOperations {
    meta:
        description = "Detects suspicious file operations such as deletion or overwriting"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "File I/O"

    strings:
        $file_delete = "File.delete()"
        $file_write = "FileOutputStream.write"
        $temp_dir = "/tmp/"
        $log_delete = "log.txt"

    condition:
        any of ($file_delete, $file_write, $temp_dir, $log_delete)
}
