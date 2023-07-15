#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174447);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/04");

  script_cve_id(
    "CVE-2022-36963",
    "CVE-2022-47505",
    "CVE-2022-47509",
    "CVE-2023-23839"
  );
  script_xref(name:"IAVA", value:"2023-A-0222");

  script_name(english:"SolarWinds Platform 2023.0 < 2023.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2023.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2023_2 advisory.

  - The SolarWinds Platform was susceptible to the Command Injection Vulnerability. This vulnerability allows
    a remote adversary with a valid SolarWinds Platform admin account to execute arbitrary commands.
    (CVE-2022-36963)

  - The SolarWinds Platform was susceptible to the Local Privilege Escalation Vulnerability. This
    vulnerability allows a local adversary with a valid system user account to escalate local privileges.
    (CVE-2022-47505)

  - The SolarWinds Platform was susceptible to the Incorrect Input Neutralization Vulnerability. This
    vulnerability allows a remote adversary with a valid SolarWinds Platform account to append URL parameters
    to inject HTML. (CVE-2022-47509)

  - The SolarWinds Platform was susceptible to the Exposure of Sensitive Information Vulnerability. This
    vulnerability allows users to access Orion.WebCommunityStrings SWIS schema object and obtain sensitive
    information. (CVE-2023-23839)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2023-23839
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?37c8c76b");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-47505
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f4bb9528");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-47509
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c5a2a21c");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-36963
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08bef5f1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2023.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36963");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-47505");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2023.0', 'max_version' : '2023.1', 'fixed_version' : '2023.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
