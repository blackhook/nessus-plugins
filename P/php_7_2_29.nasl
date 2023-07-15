#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134949);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-7064", "CVE-2020-7066");
  script_xref(name:"IAVA", value:"2020-A-0117-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"PHP 7.2.x < 7.2.29 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The version of PHP running on the remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP running on the remote web server is 7.2.x prior to 7.2.29. It is, 
therefore, affected by multiple vulnerabilities:
  
  - A NULL pointer de-reference flaw exists in PHP's Exif component due to its implementation attempting to use 
    uninitialized bytes. An unauthenticated, remote attacker can exploit this to cause a denial of service condition 
    when the application attempts to read or write memory with a NULL pointer. 
    (CVE-2020-7064)

  - An information disclosure vulnerability exists in PHP due to the `get_headers` function silently truncating 
    anything it receives, after a null byte. An unauthenticated, remote attacker can exploit this, by supplying URLs 
    containing a null byte, to disclose potentially sensitive information.
    (CVE-2020-7066)");
  script_set_attribute(attribute:"see_also", value:"https://php.net/ChangeLog-7.php#7.2.29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 7.2.29 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP", "installed_sw/PHP", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('http.inc');
include('vcf.inc');

port = get_http_port(default:80, php:TRUE);
app_info = vcf::get_app_info(app:'PHP', port:port, webapp:TRUE);
backported = get_kb_item('www/php/' + port + '/' + app_info.version + '/backported');

if ((report_paranoia < 2) && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, 'PHP ' + app_info.version + ' install');

constraints = [{'min_version':'7.2.0alpha1', 'fixed_version':'7.2.29'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
