#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118086);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Citrix NetScaler Management and Analytics System Default Administrator Credentials");

  script_set_attribute(attribute:"synopsis", value:
"A web application is protected using default administrative credentials.");
  script_set_attribute(attribute:"description", value:
"The remote Citrix NetScaler Management and Analytics System (MAS) uses a default
password ('nsroot') for the administrator account ('nsroot'). 

With this information, an attacker can gain complete administrative
access to the Citrix NetScaler appliance.");
  # http://support.citrix.com/proddocs/topic/netscaler-admin-guide-93/ns-ag-aa-reset-default-amin-pass-tsk.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74336bf9");
  script_set_attribute(attribute:"solution", value:
"Change the default administrative login credentials for nsroot.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"default credentials");

  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:netscaler");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netscaler_mas_web_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


get_kb_item_or_exit("installed_sw/NetScaler Management and Analytics System");
app = "NetScaler Management and Analytics System";

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);
get_install_count(app_name: app, exit_if_zero:TRUE);

port = get_http_port(default:80);
install = get_single_install(app_name: app, port:port);
dir = install["path"];
install_url = build_url(port:port, qs:dir);

user = 'nsroot';
pass = 'nsroot';

# Clear the cookies, in case Nessus was given credentials.
clear_cookiejar();

data = 'object={"login":{"username":"' + user + '", "password":"' + pass +'"}}';

url = "/nitro/v1/config/login";

res = http_send_recv3(
  method    : "POST",
  item             :url,
  port             :port,
  content_type     :"application/x-www-form-urlencoded",
  data             :data,
  follow_redirect  :1,
  exit_on_fail     :TRUE
);

if (!empty_or_null(res))
{
  headers = parse_http_headers(headers:res[1]);

  if (
  res[0] =~ "^HTTP/[0-9.]+ +200" &&
  headers['content-type'] =~ "^application/json; charset=UTF-8" &&
  '"message": "Invalid username or password' >!< res[2]
  )
  {
  header = "Nessus was able to gain access using the following URL";
  trailer = 
  ' and the following set of credentials: \n' +
  '\n' +
  ' Username: ' + user + '\n' +
  ' Password: ' + pass;

  report = get_vuln_report(items:dir, port:port, header:header, trailer:trailer);

  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
  exit(0);
  }
} 


audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
