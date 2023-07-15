#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17797);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-1001",
    "CVE-2007-1583",
    "CVE-2007-1649",
    "CVE-2007-1717",
    "CVE-2007-1718"
  );
  script_bugtraq_id(23105, 23357);

  script_name(english:"PHP 5.x < 5.2.2 Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.x installed on the
remote host is older than 5.2.2.  It is, therefore, affected by 
multiple vulnerabilities:

  - A heap-based buffer overflow vulnerability was found
    in PHP's gd extension. A script that could be forced to
    process WBMP images from an untrusted source could
    result in arbitrary code execution. (CVE-2007-1001)

  - A vulnerability in the way the mbstring extension
    setglobal variables was discovered where a script using
    the mb_parse_str() function to set global variables
    could be forced to to enable the register_globals
    configuration option, possibly resulting in global
    variable injection. (CVE-2007-1583)

  - A context-dependent attacker could read portions of
    heap memory by executing certain scripts with a
    serialized data input string beginning with 'S:', which
    did not properly track the number of input bytes being
    processed. (CVE-2007-1649)

  - A vulnerability in how PHP's mail() function processed
    email messages, truncating potentially important 
    information after the first ASCIIZ (\0) byte.
    (CVE-2007-1717)

  - A vulnerability in how PHP's mail() function processed
    header data was discovered. If a script sent mail using
    a subject header containing a string from an untrusted
    source, a remote attacker could send bulk email to
    unintended recipients (CVE-2007-1718).");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_2.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1649");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/11");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if (version !~ "^5\.") exit(0, "The web server on port "+port+" uses PHP "+version+" rather than 5.x.");

if (version =~ "^5\.([01]\..*|2\.[01])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.2\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
