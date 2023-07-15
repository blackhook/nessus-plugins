#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77183);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-5241", "CVE-2014-5242", "CVE-2014-5243");
  script_bugtraq_id(69135, 69136, 69137);

  script_name(english:"MediaWiki < 1.19.18 / 1.22.9 / 1.23.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version number, the instance of MediaWiki running on
the remote host is affected by the following vulnerabilities :

  - A flaw exists due to comments not being prepended to the
    JSONP callbacks. This allows a remote attacker, using a
    specially crafted SWF file, to perform a cross-site
    request forgery attack. (CVE-2014-5241)

  - A cross-site scripting vulnerability exists within the
    'mediawiki.page.image.pagination.js' script due to a
    failure to validate user-supplied input when the
    function 'ajaxifyPageNavigation' calls 'loadPage'. This
    allows a remote attacker, using a specially crafted
    request, to execute arbitrary script code within the
    trust relationship between the browser and server.
    (CVE-2014-5242)

  - A flaw exists with the iFrame protection mechanism,
    related to 'OutputPage' and 'ParserOutput', which allows
    a remote attacker to conduct a clickjacking attack.
    (CVE-2014-5243)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://lists.wikimedia.org/pipermail/mediawiki-announce/2014-July/000157.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ee4304d");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.19#MediaWiki_1.19.18");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.22#MediaWiki_1.22.9");
  script_set_attribute(attribute:"see_also", value:"https://www.mediawiki.org/wiki/Release_notes/1.23#MediaWiki_1.23.2");
  script_set_attribute(attribute:"see_also", value:"https://phabricator.wikimedia.org/T70187");
  script_set_attribute(attribute:"see_also", value:"https://phabricator.wikimedia.org/T68608");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MediaWiki version 1.19.18 / 1.22.9 / 1.23.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/13");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mediawiki:mediawiki");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mediawiki_detect.nasl");
  script_require_keys("Settings/ParanoidReport", "installed_sw/MediaWiki", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "MediaWiki";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);
version = install['version'];
install_url = build_url(qs:install['path'], port:port);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^1\.19\.(\d|1[0-7])([^0-9]|$)" ||
  version =~ "^1\.22\.[0-8]([^0-9]|$)"       ||
  version =~ "^1\.23\.[01]([^0-9]|$)"
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  set_kb_item(name:'www/'+port+'/XSRF', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n  Fixed versions    : 1.19.18 / 1.22.9 / 1.23.2' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url, version);
