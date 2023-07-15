#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119764);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/26");

  script_cve_id("CVE-2018-19518", "CVE-2018-19935", "CVE-2018-20783");
  script_bugtraq_id(106018, 106143, 107121);

  script_name(english:"PHP 5.6.x < 5.6.39 Multiple vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by
 multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web
server is 5.6.x prior to 5.6.39. It is, therefore, affected by
multiple vulnerabilities:

  - An arbitrary command injection vulnerability exists in the
  imap_open function due to improper filters for mailbox names prior
  to passing them to rsh or ssh commands. An authenticated, remote
  attacker can exploit this by sending a specially crafted IMAP server
  name to cause the execution of arbitrary commands on the target
  system. (CVE-2018-19518)

  - A denial of service (DoS) vulnerability exists in
  ext/imap/php_imap.c. An unauthenticated, remote attacker can
  exploit this issue, via an empty string in the message argument
  to the imap_mail function, to cause the application to stop
  responding. (CVE-2018-19935)

  - A heap buffer over-read exists in the phar_parse_pharfile function.
  An unauthenticated, remote attacker can exploit this to read
  allocated or unallocated memory past the actual data when trying to
  parse a .phar file. (CVE-2018-20783)");
  script_set_attribute(attribute:"see_also", value:"http://php.net/ChangeLog-5.php#5.6.39");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.6.39 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-19518");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-20783");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'php imap_open Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

# Check that it is the correct version of PHP
if (version =~ "^5(\.6)?$") audit(AUDIT_VER_NOT_GRANULAR, "PHP", port, version);
if (version !~ "^5\.6\.") audit(AUDIT_NOT_DETECT, "PHP version 5.6.x", port);

fix = "5.6.39";
if (ver_compare(ver:version, fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  Version source    : ' + source +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_HOLE );
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
