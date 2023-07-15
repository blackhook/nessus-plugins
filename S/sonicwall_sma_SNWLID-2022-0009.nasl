##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161951);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2022-1701", "CVE-2022-1702", "CVE-2022-22282");
  script_xref(name:"IAVA", value:"2022-A-0229");

  script_name(english:"SonicWall Secure Mobile Access (SMA) 12.4.x < 12.4.1-02994 Multiple Vulnerabilities (SNWLID-2022-0009)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is a SonicWall Secure Mobile Access (SMA) device that may be affected by multiple vulnerabilities:

  - SonicWall SMA1000 series firmware 12.4.0, 12.4.1-02965 and earlier versions uses a shared and hard-coded
    encryption key to store data. (CVE-2022-1701)

  - SonicWall SMA1000 series firmware 12.4.0, 12.4.1-02965 and earlier versions accept a user-controlled input
    that specifies a link to an external site and uses that link in a redirect which leads to Open redirection
    vulnerability. (CVE-2022-1702)

  - SonicWall SMA1000 series firmware 12.4.0, 12.4.1-02965 and earlier versions incorrectly restricts access
    to a resource using HTTP connections from an unauthorized actor leading to Improper Access Control
    vulnerability. (CVE-2022-22282)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2022-0009");
  script_set_attribute(attribute:"solution", value:
"Upgrade to a SonicWall SMA version that is 12.4.1-02994 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22282");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:sonicwall:firmware");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("sonicwall_sma_web_detect.nbin");
  script_require_keys("installed_sw/SonicWall Secure Mobile Access", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include('http.inc');
include('vcf.inc');

var app_name = 'SonicWall Secure Mobile Access';

get_install_count(app_name:app_name, exit_if_zero:TRUE);

# We cannot test for vulnerable models
if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var port = get_http_port(default:443, embedded:TRUE);

var app_info = vcf::get_app_info(app:app_name, port:port, webapp:TRUE);

var constraints = [
  {'min_version' : '12.4', 'fixed_version' : '12.4.1.02994', 'fixed_display' : '12.4.1-02994'}

];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
