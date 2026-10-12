rule Webshell_Generic : webshell critical
{
    meta:
        description = "Detects generic PHP and JSP webshell signatures"
        author = "Ashim"
        severity = "CRITICAL"
    strings:
        $p1 = "eval(base64_decode("
        $p2 = "passthru($_POST["
        $p3 = "system($_REQUEST["
        $p4 = "shell_exec($_GET["
        $j1 = "Runtime.getRuntime().exec(request.getParameter("
        $j2 = "ProcessBuilder(request.getParameter("
        $t1 = "BHARYDANGEROUS_FORENSIC_TEST_SIGNATURE"
    condition:
        any of them
}
