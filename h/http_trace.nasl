# @DEPRECATED@
#
# (C) Tenable Network Security, Inc.
#

# HTTP/1.1 is defined by RFC 2068
#
# Check for proxy on the way (transparent or reverse?!)
#


include("compat.inc");

if(description)
{
 script_id(11040);
 script_version ("1.37");
 script_cve_id("CVE-2004-2320", "CVE-2005-3398", "CVE-2005-3498", "CVE-2007-3008");

 script_name(english: "HTTP Reverse Proxy Detection (Deprecated)");
 script_set_attribute(attribute:"synopsis", value:
"A transparent or reverse HTTP proxy is running on this port." );
 script_set_attribute(attribute:"description", value:
"This web server is reachable through a reverse HTTP proxy.

Note: This plugin has been deprecated.
" );

 script_set_attribute(attribute:"solution", value:"Disable the HTTP reverse proxy.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-2320");
 script_cwe_id(79, 200);

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/02");
 script_cvs_date("Date: 2019/09/26 12:31:13");

script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english: "Look for an HTTP proxy on the way");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Web Servers");
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Deprecated
exit(0, 'This plugin has been deprecated.');

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 1);

r = http_send_recv3(port: port, method: 'GET', item: "/", exit_on_fail: 1);
h = parse_http_headers(status_line: r[0], headers: r[1]);
via = h["via"];
trace="";

  while(via)
  {
    # display("Via=", via, "\n");
    proxy = ereg_replace(string:via, pattern: " *([^,]*),?.*", replace: "\1");
    via = ereg_replace(string: via, pattern: "([^,]*)(, *)?(.*)", replace: "\3");
    # display(string("Proxy=", proxy, " - Via=", via, "\n"));
    proto = ereg_replace(string:proxy, 
		pattern:"^([a-zA-Z0-9_-]*/?[0-9.]+) +.*",
		replace: "\1");
    line = ereg_replace(string:proxy, 
		pattern:"^([a-zA-Z0-9_-]*/?[0-9.]+) *(.*)",
		replace: "\2");
    # display(string("Proto=", proto, "\nLine=", line, "\n"));
    if (egrep(pattern:"^[0-9]+", string: proto))
      proto = "HTTP/" + proto;
    trace = trace + proto;
    l = strlen(proto);
    for (i= l;i < 12; i=i+1) trace=trace+" ";
    trace = strcat(trace, " ", line, '\n');
  }

if (trace)
  security_warning(port: port, extra: 
strcat(
'The GET method revealed those proxies on the way to this web server :\n', trace));
else if (h["x-cache"])
{
  p = ereg_replace(pattern:'^ *[A-Z]+ +from +([^ \t\r\n]+)[ \t\r\n]+',
	string: h["x-cache"], replace: "\1");
  r = 'There might be a caching proxy on the way to this web server';
  if (p != heads) r = strcat(r, ':\n', p);
  security_warning(port: port, extra: r);
}

exit(0); # broken at this time
#
ver = get_kb_item(string("http/", port));
if (int(ver) < 11)  exit(0);	# No TRACE in HTTP/1.0

n=0;
for (i = 0; i < 99; i ++)
{
  r = http_send_recv3(port: port, method: 'TRACE', item: '/', 
  add_headers: make_array("Max-Forwards", i), exit_on_fail: 0 );
  if (isnull(r)) break;
  h = parse_http_headers(status_line: r[0], headers: r[1]);
  via = h["via"];
  if (via)
    viaL[i] = via;
  else
    viaL[i] = "?";

  if (r[0] =~ '^HTTP/[0-9.]+ +200 ')
    {
      # The proxy is supposed to send back the request it got. 
      # i.e. "TRACE / HTTP/1.1"
      # However, NetCache appliance change it to "TRACE http://srv HTTP/1.1"
      if (egrep(pattern: "^TRACE (/|http://.*) HTTP/1.1", string: r[2]))
      {
        srv = h["server"];
        if (srv)
          srvL[i+1] = srv;
        else
          srvL[i+1] = "?";
        n ++;
      }
    }
    else
      break;
}

trace="";
for (i = 1; i <= n; i = i+1)
  trace = strcat(trace, viaL[i]," - ", srvL[i], '\n');

if (n > 0)
  security_warning(port:port, protocol:"tcp",
	extra: strcat(
	'The TRACE method revealed ', n, 
	' proxy(s) between us and the web server :\n',
	trace) );
