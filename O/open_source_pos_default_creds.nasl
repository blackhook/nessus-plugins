#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(90407);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Open Source Point Of Sale Default Credentials");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is protected using
default credentials.");
  script_set_attribute(attribute:"description", value:
"The Open Source Point of Sale (POS) application running on the remote
web server uses default credentials for the administrator account. An
attacker can exploit this to gain administrative access to the
application.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/opensourcepos/opensourcepos");
  script_set_attribute(attribute:"solution", value:
"Change the password for the Open Source Point of Sale (POS) 'admin'
user.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:TF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:T/RC:C");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:open_source_point_of_sale_project:open_source_point_of_sale");
  script_set_attribute(attribute:"default_account", value:"true");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016-2022 Tenable Network Security, Inc.");

  script_dependencies("open_source_pos_detect.nbin");
  script_require_keys("installed_sw/Open Source Point of Sale");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

app = "Open Source Point of Sale";
get_install_count(app_name:app, exit_if_zero:TRUE);

user = "admin";
pass = "pointofsale";

postdata = "username="+user+"&password="+pass+"&loginButton=Go";

port = get_http_port(default:80);

install = get_single_install(
  app_name : app,
  port     : port
);
dir = install['path'];

init_cookiejar();

url      = dir + '/index.php/login';
full_url = build_url(port:port, qs:url);

# Request login page to get cookies and grab anti-CSRF token if available
res = http_send_recv3(method:'GET', item:url, port:port, follow_redirect:1, exit_on_fail:TRUE);
if (res[0] !~ '^HTTP/[0-9.]+ +200')
  exit(1, "Unexpected HTTP status code received after requesting " + full_url + ".");
if (empty_or_null(res[2]))
  exit(1, "Unexpected HTTP webpage received after requesting " + full_url + ".");

# Parse anti-CSRF token if it's available
# e.g. <input type="hidden" name="csrf_ospos_v3" value="b76305b3c67f0dc6470bc6b58e838d82" />
matches = pregmatch(string:res[2], pattern:'name="(csrf_[^"]+)" +value="([^"]+)"', icase:TRUE);
if (!isnull(matches))
  postdata += "&" + matches[1] + "=" + matches[2];  

res = http_send_recv3(
  port     : port,
  method   : "POST",
  item     : url,
  data     : postdata,
  content_type : "application/x-www-form-urlencoded",
  exit_on_fail : TRUE,
  follow_redirect : 2
);

# Unexpected responses
if (res[0] !~ '^HTTP/[0-9.]+ +200')
  exit(1, "Unexpected HTTP status code received after attempting to log in to " + full_url + ".");
if (empty_or_null(res[2]))
  exit(1, "An empty body was returned after attempting to log in.");

# Login successful with default creds
if (
  ('id="menubar"' >< res[2] || 'id="home_module_list"' >< res[2]) &&
  '>Logout<' >< res[2] &&
  'invalid username or password' >!< tolower(res[2])
)
{
  report = '\n' + 'Nessus was able to log into the ' + app + ' using the' +
           '\n' + 'following information :' +
           '\n' +
           '\n' + '  URL      : ' + full_url +
           '\n' + '  Username : ' + user +
           '\n' + '  Password : ' + pass +
           '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, build_url(port:port, qs:dir));
