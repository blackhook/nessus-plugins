#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(38701);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_name(english:"Oracle GlassFish Server Administration Console Default Credentials");
  script_summary(english:"Tries to access the console with default credentials.");

  script_set_attribute(attribute:"synopsis", value:"The remote web application server uses default credentials.");
  script_set_attribute(
    attribute:"description",
    value:
"It is possible to log into the remote Oracle GlassFish administration
console by providing default credentials.  Knowing these, an attacker
can gain administrative control of the affected application server and,
for example, install hostile applets."
  );
  script_set_attribute(attribute:"solution", value:"Change the credentials.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:ND/RC:ND");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/07");

  script_set_attribute(attribute:"plugin_type",value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:glassfish_server");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("glassfish_console_detect.nasl");
  script_exclude_keys("global_settings/supplied_logins_only");
  script_require_keys("www/glassfish", "www/glassfish/console");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("glassfish.inc");
include("webapp_func.inc");

#
# Main
#

# Check GlassFish & GlassFish Admin Console
get_kb_item_or_exit('www/glassfish');
get_kb_item_or_exit('www/glassfish/console');

port = get_glassfish_console_port(default:4848);

if (supplied_logins_only)
  audit(AUDIT_SUPPLIED_LOGINS_ONLY);

clear_cookiejar();

# Get the previously-detected version of GlassFish so we know which
# credentials to use, etc.
version = get_kb_item_or_exit('www/' + port + '/glassfish/version');
user = 'admin';
if (version =~ "^2")
{
  title = "<title>.*GlassFish.*Admin Console</title>";
  pass_list = ['adminadmin'];
}
else if ((version =~ "^3") || (version =~ "^4") || (version =~ "^5"))
{
  title = "Common Tasks";
  pass_list = ['', 'admin'];
}
else
  exit(0, 'No known default credentials for Oracle GlassFish version ' + version + ' on port ' + port + '.');

# Access the login page of the administration console so we can get a
# cookie for a session.
url = '/j_security_check';
res = get_glassfish_res(url:url, port:port);

if (empty_or_null(get_http_cookie(name:'JSESSIONID')))
  exit(1, 'Failed to parse value from Set-Cookie header.');

# GlassFish sometimes could be slow to respond
http_set_read_timeout(40);

# Attempt to log in with default credentials.
foreach pass (pass_list)
{
  res = get_glassfish_res(
    port            : port,
    method          : 'POST',
    url             : url,
    add_headers     : make_array('Content-Type', 'application/x-www-form-urlencoded'),
    data            : 'j_username=' + user + '&j_password=' + pass
  );

  if ('Location' >< res[1])
    res = get_glassfish_res(
      port            : port,
      add_headers     : make_array('Content-Type', 'application/x-www-form-urlencoded'),
      follow_redirect : 2
    );

  if (title >< res[2])
    break;
}

# Check that target is actually responding to requests
if (empty_or_null(res))
  audit(AUDIT_SVC_FAIL, 'Oracle GlassFish', port);

# Check returned page to see if it is actually the administrative interface.
if (res[2] !~ title)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Oracle GlassFish', build_glassfish_url(url:'/', port:port));

security_report_v4(
  port        : port,
  severity    : SECURITY_HOLE,
  extra       : 'Nessus was able to gain access using the following URL\n\n' +
    build_glassfish_url(url:'/', port:port) + '\n\n' +
    'and the following set of credentials :' +
    '\n' +
    '\n  Username : ' + user +
    '\n  Password : ' + pass +
    '\n'
  );

exit(0);
