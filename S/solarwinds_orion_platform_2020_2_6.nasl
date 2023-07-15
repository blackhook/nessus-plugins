#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155442);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/12/30");

  script_cve_id("CVE-2021-35213", "CVE-2021-35215");
  script_xref(name:"IAVA", value:"2021-A-0477-S");

  script_name(english:"SolarWinds Orion Platform 2020.2.0 < 2020.2.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Orion Platform installed on the remote host is prior to 2020.2.6. It is, therefore, affected
by multiple vulnerabilities as referenced in the orion_platform_2020_2_6 advisory.

  - An Improper Access Control Privilege Escalation Vulnerability was discovered in the User Setting of Orion
    Platform version 2020.2.5. It allows a guest user to elevate privileges to the Administrator using this
    vulnerability. Authentication is required to exploit the vulnerability. (CVE-2021-35213)

  - Insecure deserialization leading to Remote Code Execution was detected in the Orion Platform version
    2020.2.5. Authentication is required to exploit this vulnerability. (CVE-2021-35215)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35213
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2d8616f");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2021-35215
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f74c2dd");
  script_set_attribute(attribute:"solution", value:
"");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/11/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'min_version' : '2020.2.0', 'max_version' : '2020.2.5', 'fixed_version' : '2020.2.6' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
