#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78603);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-0050", "CVE-2014-0224");
  script_bugtraq_id(65400, 67899);

  script_name(english:"Oracle Endeca Information Discovery Studio Multiple Vulnerabilities (October 2014 CPU)");
  script_summary(english:"Checks the version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of Oracle Endeca Information
Discovery Studio that may be missing a vendor-supplied security patch
that fixes multiple bugs and OpenSSL related security vulnerabilities.

Note that depending on how the remote host is configured, Nessus may
not be able to detect the correct version. You'll need to manually
verify that the remote host has not been patched.");
  # https://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ada40cc");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2014 Oracle
Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0050");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_endeca_information_discovery_studio_detect.nbin");
  script_require_keys("installed_sw/Oracle Endeca Information Discovery Studio", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app_name = "Oracle Endeca Information Discovery Studio";

port = get_http_port(default:8080);

install = get_single_install(app_name:app_name, port:port, exit_if_unknown_ver:TRUE);

version = install["version"];
dir = install["path"];

install_url = build_url(port:port, qs:dir);

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (
  (version =~ "^3\.0\." && ver_compare(ver:version, fix:"3.0.18092", strict:FALSE) == -1) ||
  (version =~ "^3\.1\." && ver_compare(ver:version, fix:"3.1.18915", strict:FALSE) == -1) ||
  (version =~ "^2\.4\.0\.") ||
  (version =~ "^2\.3\." && ver_compare(ver:version, fix:"2.3.18835", strict:FALSE) == -1) ||
  (version =~ "^2\.2\.2\." && ver_compare(ver:version, fix:"2.2.2.17777", strict:FALSE) == -1) ||
  (version =~ "^2\.2\.[0-2]$")
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + install_url +
      '\n  Installed version : ' + version +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app_name, install_url, version);
