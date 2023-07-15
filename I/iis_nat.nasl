#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10759);
  script_version("1.63");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2000-0649");
  script_bugtraq_id(1499);

  script_name(english:"Web Server HTTP Header Internal IP Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"This web server leaks a private IP address through its HTTP headers.");
  script_set_attribute(attribute:"description", value:
"This may expose internal IP addresses that are usually hidden or
masked behind a Network Address Translation (NAT) Firewall or proxy
server. 

There is a known issue with Microsoft IIS 4.0 doing this in its default
configuration. This may also affect other web servers, web applications,
web proxies, load balancers and through a variety of misconfigurations
related to redirection.");
  # https://web.archive.org/web/20000819132257/http://archives.neohapsis.com/archives/ntbugtraq/2000-q3/0025.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe24f941");
  # https://support.microsoft.com/en-us/topic/fix-the-internal-ip-address-of-an-iis-7-0-server-is-revealed-if-an-http-request-that-does-not-have-a-host-header-or-has-a-null-host-header-is-sent-to-the-server-c493e9bc-dfd3-0d9b-941c-b2d93a957d9e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e23582e");
  # https://blogs.msdn.microsoft.com/asiatech/2009/03/12/why-private-ip-address-is-still-revealed-on-iis-server-even-after-applying-fix-834141/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eedfe2d");
  script_set_attribute(attribute:"solution", value:
"Apply configuration suggested by vendor.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2000-0649");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/09/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http5.inc");
include("misc_func.inc");
include("spad_log_func.inc");
include("obj.inc");

if ( report_paranoia == 0 )
  if ( ! all_addr_public )  exit(0, "Exiting due to the network not being public.");
else if ( all_addr_private ) exit(0, "Exiting due to the network being private.");

dirs = get_kb_list("www/" + port + "/content/directories");
if ( isnull(dirs) ) dirs = make_list("/");
else dirs = make_list(dirs);

port = get_http_port(default:80);

# It sometimes works with an non existing URI
uri = dirs[0] + "/" + rand_str() + ".asp";
items_l = make_list(dirs[0], uri);

foreach item (items_l)
{
  res = http_send_recv3(port:port, method:"GET", version:10, item:item, exit_on_fail:TRUE);
  if (empty_or_null(res)){
    audit(AUDIT_RESP_NOT, port, "HTTP 1.0 GET request");
  }
  spad_log(message:"http response:\n" + obj_rep(res));
  spad_log(message:"http last sent request:\n" + http_last_sent_request());

  # Check for private IP addresses in the banner
  # Ranges are: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
  pat = "(Location|Content-Location|WWW-Authenticate):[^,]*((10\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])|192\.168)\.\d{1,3}\.\d{1,3})(,|[^0-9.])";
  private_ip = pregmatch(pattern:pat, string:res[1]);
  if(
    !isnull(private_ip) && 
    private_ip[2] != get_host_ip() &&
    !pgrep(pattern:"(^X-ORCL-.+: *|Oracle.*)10\.", string:res[1])
  )
  {
    security_report_v4(port:port, severity:SECURITY_NOTE, request:[http_last_sent_request()], output:res[1], generic:TRUE);
    exit(0);
  }
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED,port);
