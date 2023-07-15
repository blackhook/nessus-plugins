#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(73521);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(65553);

  script_name(english:"Liferay Portal 6.2.0 CE GA1 Multiple XSS");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of Liferay
Portal running on the remote host is 6.2.0. It is, therefore,
potentially affected by the following cross-site scripting
vulnerabilities :

  - Input passed from page titles is not sanitized before
    it is displayed in the Recycle Bin.

  - Input passed from user profiles is not validated before
    being displayed in the Polls.

  - Input passed from user profiles is not validated before
    being displayed in the History tab.

  - Input passed from user profiles is not validated before
    displaying it to the admin.

  - Input passed from user profiles is not validated before
    being displayed in the bookmarks.

  - Input passed from the Look and Feel dialogs is not
    validated before being returned to the user.

  - Input when displaying search results is not validated
    for various portlets.

  - Input for scheduled publish-to-live events are not
    validated before being returned to users.

  - Input from article titles is not validated before
    being displayed in the print mode.

  - Input from page titles, when selecting a scope for a
    portlet, is not validated before being returned to the
    user.

  - Input to the title of a post priority is not validated
    before being returned to the user.

  - Input passed from page titles using the Site Map is not
    validated before being returned to the user.

  - Input from page links in DDL is not validated before
    being returned to the user.

These flaws could allow a remote attacker with a specially crafted
request to execute arbitrary code within the trust relationship
between the browser and server.

Note that Nessus has not tested for these issues or determined if the
patch has been applied but has instead relied only on the
application's self-reported version number.");
  # https://web.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-43809-various-xss-issues-in-liferay-portal-6-2-0?redirect=http%3A%2F%2Fwww.liferay.com%2Fcommunity%2Fsecurity-team%2Fknown-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?db3b47ec");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 6.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detect.nasl");
  script_require_keys("www/liferay_portal");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80, 443, 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");
include("webapp_func.inc");

port = get_http_port(default:8080, embedded:TRUE);

if (!get_kb_item("www/liferay_portal")) audit(AUDIT_WEB_APP_NOT_INST, "Liferay Portal", port);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Liferay Portal", url);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Version 6.2.0 is vulnerable.
fix = "6.2.1";
if (ver !~ "^6\.2") audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

# Report our findings.
set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}
security_warning(port:port, extra:report);
