#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62926);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");
  script_bugtraq_id(55573);

  script_name(english:"Liferay Portal 6.1.0 / 6.1.10 Arbitrary File Deletion");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a file deletion vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the installation of Liferay
Portal hosted on the remote web server is affected by an arbitrary file
deletion vulnerability.  A user who has permission to delete an
attachment in the Wiki portlet can delete any arbitrary file on the
server. 

Note that Nessus has not tested for this issue or checked if a
workaround has been applied but has instead relied only on its
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://issues.liferay.com/browse/LPS-28934");
  # https://web.liferay.com/community/security-team/known-vulnerabilities/-/asset_publisher/T8Ei/content/cst-sa-lps-28934-delete-any-file-on-the-server-wiki-
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?66af3563");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Liferay Portal 6.1.1 / 6.1.20 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/11/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:portal");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 Tenable Network Security, Inc.");

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

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Get the ports that web servers have been found on, defaulting to
# what Liferay uses with Tomcat, their recommended bundle.
port = get_http_port(default:8080, embedded:TRUE);

# Get details of the Liferay Portal install.
install = get_install_from_kb(appname:"liferay_portal", port:port, exit_on_fail:TRUE);
dir = install["dir"];
ver = install["ver"];
url = build_url(port:port, qs:dir + "/");

if (ver == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Liferay Portal", url);

# Versions 6.1.0 and 6.1.10 are vulnerable.
if (ver != "6.1.0" && ver != "6.1.10") 
  audit(AUDIT_WEB_APP_NOT_AFFECTED, "Liferay Portal", url, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : 6.1.1 / 6.1.20' +
    '\n';
}
security_warning(port:port, extra:report);
