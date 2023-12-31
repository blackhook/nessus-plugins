#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86898);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2015-8103");
  script_bugtraq_id(77636);
  script_xref(name:"CERT", value:"576313");

  script_name(english:"Jenkins < 1.638 / 1.625.2 Java Object Deserialization RCE");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote web server hosts a version of Jenkins or Jenkins Enterprise
that is prior to 1.638 or 1.625.2. It is, therefore, affected by a
flaw in the Apache Commons Collections (ACC) library that allows the
deserialization of unauthenticated Java objects. An unauthenticated,
remote attacker can exploit this to execute arbitrary code on the
target host.");
  # https://jenkins-ci.org/content/mitigating-unauthenticated-remote-code-execution-0-day-jenkins-cli
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0316bc02");
  # https://foxglovesecurity.com/2015/11/06/what-do-weblogic-websphere-jboss-jenkins-opennms-and-your-application-have-in-common-this-vulnerability/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c6d83db");
  script_set_attribute(attribute:"see_also", value:"https://github.com/jenkinsci-cert/SECURITY-218");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/COLLECTIONS-580");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Jenkins version 1.638 / 1.625.2 or later. Alternatively,
disable the CLI port per the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-8103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'OpenNMS Java Object Unserialization Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cloudbees:jenkins");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jenkins_detect.nasl");
  script_require_keys("www/Jenkins");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);
get_kb_item_or_exit("www/Jenkins/"+port+"/Installed");

# LTS has a different version number
is_LTS = get_kb_item("www/Jenkins/"+port+"/is_LTS");
if (is_LTS)
{
  appname = "Jenkins Open Source LTS";
  fixed = "1.625.2";
}
else
{
  appname = "Jenkins Open Source";
  fixed = "1.638";
}

# check the patched versions
version = get_kb_item_or_exit("www/Jenkins/"+port+"/JenkinsVersion");
if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, appname);
if (ver_compare(ver: version, fix: fixed, strict: FALSE) >= 0) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

# if the version is less than the patch version then check to see if the CLI port is enabled
url = build_url(qs:'/', port: port);
res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);
if (("X-Jenkins-CLI-Port" >!< res[1]) &&
  ("X-Jenkins-CLI2-Port" >!< res[1]) &&
  ("X-Hudson-CLI-Port" >!< res[1])) audit(AUDIT_INST_VER_NOT_VULN, appname, version);

# Find a CLI port to examine
item = eregmatch(pattern:"X-Jenkins-CLI-Port:\s*([0-9]+)[ \r\n]", string: res[1]);
if (isnull(item))
{
  item = eregmatch(pattern:"X-Hudson-CLI-Port:\s*([0-9]+)[ \r\n]", string: res[1]);
  if (isnull(item))
  {
    item = eregmatch(pattern:"X-Jenkins-CLI2-Port:\s*([0-9]+)[ \r\n]", string: res[1]);
    if (isnull(item)) audit(AUDIT_RESP_BAD, port);
  }
}

sock = open_sock_tcp(item[1]);
if (!sock) audit(AUDIT_NOT_LISTEN, appname, item[1]);

send(socket: sock, data: '\x00\x14' +  "Protocol:CLI-connect");
return_val = recv(socket: sock, length: 20, min: 9, timeout: 1);
close(sock);

if (isnull(return_val) || len(return_val) < 9) audit(AUDIT_RESP_BAD, res[1]);
if ("Unknown protocol:" >< return_val) audit(AUDIT_INST_VER_NOT_VULN, appname, version);
else if ("Welcome" >!< return_val) audit(AUDIT_RESP_BAD, res[1]);

if (report_verbosity > 0)
{    
  report =
      '\n  Port              : ' + item[1] +
      '\n  Product           : ' + appname +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
  security_hole(port: item[1], extra: report);
}
else security_hole(item[1]);
exit(0);
