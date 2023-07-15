#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16276);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(12398);

  script_name(english:"phpPgAds dest Parameter HTTP Response Splitting");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is vulnerable to HTTP response splitting.");
  script_set_attribute(attribute:"description", value:
"There is a flaw in the remote phpPgAds/phpAdsNew, a banner management
and tracking system written in PHP.

This version of phpPgAds/phpAdsNew is affected by an HTTP response
splitting vulnerability.

An attacker, exploiting this flaw, would be able to redirect users to
another site to perform another attack (steal their credentials).");
  script_set_attribute(attribute:"solution", value:
"Upgrade to phpPGAds/phpAdsNew 2.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phppgadmin:phppgadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("webmirror.nasl", "http_version.nasl");
  script_require_keys("www/PHP");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var u, r;
 u = strcat(loc, "admin/index.php");
 r = http_send_recv3(port: port, method: "GET", item: u);
 if (isnull(r)) exit(0);

 if ( egrep(pattern:"<meta name='generator' content='(phpPgAds|phpAdsNew) ([0-1]\..*|2\.0|2\.0\.[0-1]) - http://www\.phpadsnew\.com'>", string:r[2]))
 {
   security_warning(port);
   exit(0);
 }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

