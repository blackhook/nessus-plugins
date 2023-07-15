#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25971);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-1413",
    "CVE-2007-2872",
    "CVE-2007-3294",
    "CVE-2007-3378",
    "CVE-2007-3790",
    "CVE-2007-3799",
    "CVE-2007-3806",
    "CVE-2007-4010",
    "CVE-2007-4033",
    "CVE-2007-4255",
    "CVE-2007-4507",
    "CVE-2007-4652",
    "CVE-2007-4658",
    "CVE-2007-4659",
    "CVE-2007-4660",
    "CVE-2007-4661",
    "CVE-2007-4662",
    "CVE-2007-4663"
  );
  script_bugtraq_id(
    24261,
    24661,
    24922,
    25498
  );

  script_name(english:"PHP < 5.2.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.2.4.  Such versions may be affected by various
issues, including but not limited to several overflows.");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_4.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 22, 119, 189, 362, 399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2022 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.[0-3]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.4\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
