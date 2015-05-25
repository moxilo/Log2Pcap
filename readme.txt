Apache combined (default)
	Examples:
		10.0.1.2 - - [24/Apr/2010:14:33:22 -0700] "GET /feed/ HTTP/1.1" 200 16605 "-" "Apple-PubSub/65.12.1" SxPq9AoAAQ4AAEHGCtEAAAAD 967817
		172.16.2.128 - - [03/Sep/2012:23:18:51 +0200] "GET /F2UMWNgN.orig HTTP/1.1" 404 529 "-" "Mozilla/5.00 (Nikto/2.1.5) (Evasions:None) (Test:map_codes)"

IIS W3C Extended
	Info:   http://www.loganalyzer.net/log-analyzer/w3c-extended.html
	Format: date time IPsrc - IPdst Method query - codereturn X X X HTTPVersion UserAgent Var Referer
	Examples:     
		1998-11-19 22:48:39 206.175.82.5 - 208.201.133.173 GET /global/images/navlogboards.gif - 200 540 324 157 HTTP/1.0 Mozilla/4.0+(compatible;+MSIE+4.01;+Windows+95) USERID=CustomerA;+IMPID=01234 http://www.loganalyzer.net
		2002-05-24 20:18:01 172.224.24.114 - 206.73.118.24 80 GET /Default.htm - 200 7930 248 31 HTTP/1.0 Mozilla/4.0+(compatible;+MSIE+5.01;+Windows+2000+Server) http://64.224.24.114/

IIS Log File Format
        Info:   http://www.microsoft.com/technet/prodtechnol/WindowsServer2003/Library/IIS/c93b2856-76c4-4348-9d46-8a60612c3b23.mspx?mfr=true
                http://www.loganalyzer.net/log-analyzer/iis-log-file-format.html
        Format: Ipsrc, -, date, time, -, -, ipdst, -, -, -, returncode, -, methode, query, -,
        Examples:     
		192.168.114.201, -, 03/20/01, 7:55:20, W3SVC2, SALES1, 172.21.13.45, 4502, 163, 3223, 200, 0, GET, /DeptLogo.gif, -,

IBM Webseal default log
        Examples:     
		XX.XX.XX.XX - Unauth [01/Oct/2011:10:21:17 +0700] "GET / HTTP/1.0" 200 123
                XX.XX.XX.XX - Unauth [01/Oct/2011:10:21:19 +0700] "GET /index.php HTTP/1.1" 200 432

Nginx File Format
        Info:   http://articles.slicehost.com/2010/8/27/reading-nginx-web-logs
        Example:     
		80.154.42.54 - - [23/Aug/2010:15:25:35 +0000] "GET /phpmy-admin/scripts/setup.php HTTP/1.1" 404 347 "-" "ZmEu"
                123.65.150.10 - - [23/Aug/2010:03:50:59 +0000] "POST /wordpress3/wp-admin/admin-ajax.php HTTP/1.1" 200 2 "http://www.example.com/wordpress3/wp-admin/post-new.php" "Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_6_4; en-US) AppleWebKit/534.3 (KHTML, like Gecko) Chrome/6.0.472.25 Safari/534.3"

Tomcat:
	Examples:
		10.1.1.1 - - [31/Oct/2010:09:02:00 -0500] "GET /example.html?foo=bar HTTP/1.1" 200 999