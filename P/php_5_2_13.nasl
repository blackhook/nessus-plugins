#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(44921);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2010-1128", "CVE-2010-1129", "CVE-2010-1130");
  script_bugtraq_id(38182, 38430, 38431);
  script_xref(name:"SECUNIA", value:"38708");

  script_name(english:"PHP < 5.3.2 / 5.2.13 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is older than 5.3.2 / 5.2.13.  Such versions may be affected by
several security issues :

  - Directory paths not ending with '/' may not be
    correctly validated inside 'tempnam()' in 
    'safe_mode' configuration.

  - It may be possible to bypass the 'open_basedir'/ 
    'safe_mode' configuration restrictions due to an
    error in session extensions.

  - An unspecified vulnerability affects the LCG entropy.");
  script_set_attribute(attribute:"see_also", value:"http://securityreason.com/achievement_securityalert/82");
  script_set_attribute(attribute:"see_also", value:"http://securityreason.com/securityalert/7008");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/fulldisclosure/2010/Feb/208");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_3_2.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.3.2");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_13.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.2.13");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.3.2 / 5.2.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

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

if (version =~ "^[0-4]\." ||
    version =~ "^5\.[01]\." ||
    version =~ "^5\.2\.([0-9]|1[0-2])($|[^0-9])" ||
    version =~ "^5\.3\.[01]($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.3.2 / 5.2.13\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
