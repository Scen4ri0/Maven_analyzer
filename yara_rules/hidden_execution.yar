rule HiddenExecution {
    meta:
        description = "Detects hidden or persistent execution mechanisms"
        author = "Scen4ri0"
        date = "2024-12-26"
        category = "Execution"

    strings:
        $while_true = "while(true)"
        $infinite_loop = "for(;;)"
        $thread_run = "new Thread().start()"
        $scheduler = "ScheduledExecutorService.schedule"

    condition:
        any of ($while_true, $infinite_loop, $thread_run, $scheduler)
}
