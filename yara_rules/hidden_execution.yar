rule HiddenExecution {
    meta:
        description = "Detects hidden or persistent execution mechanisms with suspicious patterns"
        author = "Scen4ri0"
        date = "2024-12-27"
        category = "Execution"

    strings:
        $while_true = "while(true)"
        $infinite_loop = "for(;;)"
        $thread_run = "new Thread().start()"
        $scheduler = "ScheduledExecutorService.schedule"
        $blocking_call = "Thread.sleep"
        $executor_service = "Executors.newFixedThreadPool"

    condition:
        (
            ($while_true or $infinite_loop) and not $blocking_call
        ) or
        (
            $thread_run and not ($scheduler or $executor_service)
        ) or
        (
            $scheduler and not $executor_service
        )
}
