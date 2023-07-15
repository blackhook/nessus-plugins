#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156886);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-35247");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/02/04");
  script_xref(name:"IAVA", value:"2022-A-0047-S");

  script_name(english:"Serv-U FTP Server < 15.3 Improper Input Validation");

  script_set_attribute(attribute:"synopsis", value:
"The remote FTP server is affected by an Improper Input Validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the installed version of Serv-U is a version prior to 15.3. It is, therefore, 
affected by an improper input validation vulnerability. The Serv-U web login screen to LDAP authentication
was allowing characters that were not sufficiently sanitized.

SolarWinds has updated the input mechanism to perform additional validation and sanitization.

Please Note: No downstream effect has been detected as the LDAP servers ignored improper characters.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35247
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e920478f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ServU-FTP 15.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35247");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u_file_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:serv-u");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("servu_version.nasl");
  script_require_keys("installed_sw/Serv-U");

  exit(0);
}

include('vcf.inc');
include('ftp_func.inc');

var port = get_ftp_port(default:21);

var app_info = vcf::get_app_info(app:'Serv-U', port:port);

var constraints = [
  {'fixed_version' : '15.3'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
