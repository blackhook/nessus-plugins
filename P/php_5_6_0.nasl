#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78556);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2013-6712",
    "CVE-2013-7226",
    "CVE-2013-7327",
    "CVE-2013-7345",
    "CVE-2014-0185",
    "CVE-2014-0207",
    "CVE-2014-0236",
    "CVE-2014-0237",
    "CVE-2014-0238",
    "CVE-2014-1943",
    "CVE-2014-2270",
    "CVE-2014-2497",
    "CVE-2014-3478",
    "CVE-2014-3479",
    "CVE-2014-3480",
    "CVE-2014-3487",
    "CVE-2014-3515",
    "CVE-2014-3538",
    "CVE-2014-3587",
    "CVE-2014-3597",
    "CVE-2014-3981",
    "CVE-2014-4049",
    "CVE-2014-4670",
    "CVE-2014-4698",
    "CVE-2014-4721",
    "CVE-2014-5120"
  );
  script_bugtraq_id(
    64018,
    65533,
    65596,
    65668,
    66002,
    66233,
    66406,
    67118,
    67759,
    67765,
    67837,
    68007,
    68120,
    68237,
    68238,
    68239,
    68241,
    68243,
    68348,
    68423,
    68511,
    68513,
    69322,
    69325,
    69375,
    90957
  );

  script_name(english:"PHP 5.6.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is a development version of 5.6.0. It is, therefore, affected by
multiple vulnerabilities.

Note that Nessus has not attempted to exploit this issue but has
instead relied only on application's self-reported version number.");
  # http://git.php.net/?p=php-src.git;a=commitdiff;h=f3f22ff5c697aef854ffc1918bce708b37481b0f
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab45889c");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=67329");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.0");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the stable version of PHP 5.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3515");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);
php = get_php_from_kb(port: port, exit_on_fail: TRUE);

version = php["ver"];
source  = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported) audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.0(alpha|beta|RC|rc)")
  audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);

if (report_verbosity > 0)
{
  report =
    '\n  Version source    : '+source +
    '\n  Installed version : '+version+
    '\n  Fixed version     : 5.6.0\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
exit(0);
