#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134944);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/13");

  script_cve_id("CVE-2020-7064", "CVE-2020-7065", "CVE-2020-7066");
  script_xref(name:"IAVA", value:"2020-A-0117-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"PHP 7.3.x < 7.3.16 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 7.3.x prior to 7.3.16. It is,
therefore, affected by the following vulnerabilities:

  - An out of bounds read resulting in the use of an uninitialized value in exif. (CVE-2020-7064)

  - A stack buffer overflow in mb_strtolower() allows overwriting of a stack-allocated buffer with an overflown array from 
    .rodata. (CVE-2020-7065)

  - get_headers() silently truncates anything after a null byte in the URL it uses. An unauthenticated, remote
    attacker can exploit this to leak sensitive information or cause the web server to unexpectedly process
    attacker-controlled data. (CVE-2020-7066)
    
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.php.net/ChangeLog-7.php#7.3.16");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.3.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7065");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}
include('http.inc');
include('vcf.inc');
include('audit.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);

backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported) audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [ {'min_version':'7.3.0alpha1', 'fixed_version':'7.3.16'} ];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
