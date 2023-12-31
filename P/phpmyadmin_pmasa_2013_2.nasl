#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66295);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-3238",
    "CVE-2013-3239",
    "CVE-2013-3240",
    "CVE-2013-3241"
  );
  script_bugtraq_id(
    59460,
    59461,
    59462,
    59465
  );
  script_xref(name:"EDB-ID", value:"25003");

  script_name(english:"phpMyAdmin 3.5.x < 3.5.8.1 / 4.x < 4.0.0-rc3 Multiple Vulnerabilities (PMASA-2013-2 - PMASA-2013-5");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-identified version number, the phpMyAdmin 3.5.x /
4.0.0 install hosted on the remote web server is earlier than 3.5.8.1 /
4.0.0-rc3 and is, therefore, affected by multiple vulnerabilities:

  - The 'preg_replace' fails to properly sanitize
    arguments, which can be used to for arbitrary code
    execution. (CVE-2013-3238)

  - A security weakness exists in the way that locally saved
    databases are handled.  It is possible that the
    'filename_template' parameter can be used to create a
    file with double extensions. (CVE-2013-3239)

  - A flaw exists where the 'what' parameter was not
    correctly validated, allowing for a local file
    inclusion. This flaw reportedly affects phpMyAdmin 4.x
    only. (CVE-2013-3240)

  - A flaw exists in the 'export.php' script that allows
    overwrite of global variables, leading to an
    unauthorized access vulnerability. This flaw reportedly
    affects phpMyAdmin 4.x only. (CVE-2013-3241)");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2013-2/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2013-3/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2013-4/");
  script_set_attribute(attribute:"see_also", value:"https://www.phpmyadmin.net/security/PMASA-2013-5/");
  script_set_attribute(attribute:"see_also", value:"http://www.waraxe.us/advisory-103.html");
  script_set_attribute(attribute:"solution", value:
"Either upgrade to phpMyAdmin 3.5.8.1 / 4.0.0-rc3 or later, or apply the
patches from the referenced link.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'phpMyAdmin Authenticated Remote Code Execution via preg_replace()');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:phpmyadmin:phpmyadmin");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("phpMyAdmin_detect.nasl");
  script_require_keys("www/PHP", "www/phpMyAdmin", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:"phpMyAdmin", port:port, exit_on_fail:TRUE);
dir = install['dir'];
location = build_url(qs:dir, port:port);

version = install['ver'];
if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "phpMyAdmin", location);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  version =~ "^3(\.5)?$" ||
  version =~ "^4(\.0)?$"
) exit(1, "The version of phpMyAdmin located at "+ location +" ("+ version +") is not granular enough.");

if (
  # 3.5.x < 3.5.8.1
  version =~ "^3\.5\.[0-7]([^0-9]|$)" ||
  version =~ "^3\.5\.8($|\.[^1-9])" ||
  # 4.0.0 < 4.0.0-rc3
  version =~ "^4\.0\.0-rc[0-2]([^0-9]|$)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + location +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.5.8.1 / 4.0.0-rc3' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "phpMyAdmin", location, version);
