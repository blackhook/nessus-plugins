#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(42982);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(37157);

  script_name(english:"AWStats < 6.95 awredir.pl Arbitrary Site Redirect");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a Perl script that is affected by an open
redirect vulnerability.");
  script_set_attribute(attribute:"description", value:
"The 'awredir.pl' script, available through the remote web server as
part of an AWStats installation, is affected by an open redirect
vulnerability. An attacker can exploit this issue to conduct phishing
attacks by tricking users into visiting malicious websites.");
  # http://www.awstats.org/docs/awstats_changelog.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?597373d3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to AWStats version 6.95 or later if necessary. And make sure
the variable '$KEYFORMD5' defined in the affected script is set to a
personalized value.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available for this vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:laurent_destailleur:awstats");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("awstats_detect.nasl");
  script_require_keys("www/AWStats");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80);

install = get_install_from_kb(appname:'AWStats', port:port);
if (isnull(install)) exit(0, "The 'www/"+port+"/AWStats' KB item is missing.");
dir = install['dir'];

# Try to exploit the issue.
redirect = "http://www.example.com";
url = dir + "/awredir.pl?" + "url=" + redirect;

res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (isnull(hdrs['location'])) location = "";
else location = hdrs['location'];

# There's a problem if ...
if (
  # we're redirected and ...
  code == 302 &&
  # it's to the location we specified
  redirect == location
)
{
  if (report_verbosity > 0)
  {
    report = '\n' +
      'Nessus was able to verify the issue using the following URL :' + '\n' +
      '\n' +
      ' ' + build_url(port:port, qs:url) + '\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The AWStats install at "+build_url(port:port, qs:dir+"/awstats.pl")+" is not affected.");
