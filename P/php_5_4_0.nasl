#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122590);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2011-2483", "CVE-2011-3389", "CVE-2011-4153");
  script_bugtraq_id(49241, 49778, 51417);
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"PHP 5.4.x < 5.4.0 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP installed on the remote
host is 5.4.x earlier than 5.4.0, and, therefore, potentially affected
by multiple vulnerabilities :

  - crypt_blowfish as used in PHP does not properly handle
    8-bit characters, which makes it easier for
    context-dependent attackers to determine a cleartext
    password by leveraging knowledge of a password hash.
    (CVE-2011-2483)

  - Multiple NULL Pointer Dereference with the
    zend_strndup() fucntion could allow a remote attacker
    to cause a denial of service. (CVE-2011-4153)

  - A flaw in SSL sockets with SSL 3.0 / TLS 1.0 was
    addressed. (CVE-2011-3389)

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://bugs.php.net/bug.php?id=55748");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.4.0");
  script_set_attribute(attribute:"see_also", value:"http://php.net/releases/5_4_0.php");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.4.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-2483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("http.inc");
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

if (version =~ "^5(\.4)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.4\.") audit(AUDIT_NOT_DETECT, "PHP version 5.4.x", port);

if (version =~ "^5\.4\.0(alpha|beta|rc|RC)")
{
  report =
    '\n  Version source    : '+source +
    '\n  Installed version : '+version+
    '\n  Fixed version     : 5.4.0\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
