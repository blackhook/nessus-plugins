#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138593);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2020-8169");
  script_xref(name:"IAVA", value:"2020-A-0319-S");

  script_name(english:"PHP 7.2.x < 7.2.32 / 7.3.x < 7.3.20 / 7.4.x < 7.4.8 Information Disclosure");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by an information disclosure vulnerability");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of PHP running on the remote Windows web server is 7.2.x
prior to 7.2.32, 7.3.x prior to 7.3.20 or 7.4.x prior to 7.4.8. It is, therefore, affected by an information disclosure
vulnerability. The libcurl library can be tricked to prepend a part of the password to the host name before it resolves
it, potentially leaking the partial password over the network and to the DNS server(s).");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/releases/7_2_32.php");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/releases/7_3_20.php");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/releases/7_4_8.php");
  script_set_attribute(attribute:"see_also", value:"https://curl.haxx.se/docs/CVE-2020-8169.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP 7.2.32, 7.3.20, 7.4.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl", "os_fingerprint.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP", "Host/OS");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

os = get_kb_item_or_exit('Host/OS');
if ('windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, 'Windows');

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');
if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [
  {'min_version':'7.2.0alpha1', 'fixed_version':'7.2.32'},
  {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.20'},
  {'min_version':'7.4.0alpha1', 'fixed_version':'7.4.8'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
