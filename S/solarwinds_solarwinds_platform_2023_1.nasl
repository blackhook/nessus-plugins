#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171516);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/02");

  script_cve_id(
    "CVE-2022-38111",
    "CVE-2022-47503",
    "CVE-2022-47504",
    "CVE-2022-47506",
    "CVE-2022-47507",
    "CVE-2023-23836"
  );
  script_xref(name:"IAVA", value:"2023-A-0104-S");

  script_name(english:"SolarWinds Platform 2023.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Platform installed on the remote host is prior to 2023.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2023_1 advisory.

  - SolarWinds Platform version 2022.4.1 was found to be susceptible to the Deserialization of Untrusted Data.
    This vulnerability allows a remote adversary with Orion admin-level account access to the SolarWinds Web
    Console to execute arbitrary commands. (CVE-2023-23836)

  - SolarWinds Platform was susceptible to the Deserialization of Untrusted Data. This vulnerability allows a
    remote adversary with Orion admin-level account access to SolarWinds Web Console to execute arbitrary
    commands. (CVE-2022-38111, CVE-2022-47503, CVE-2022-47504, CVE-2022-47507)

  - SolarWinds Platform was susceptible to the Directory Traversal Vulnerability. This vulnerability allows a
    local adversary with authenticated account access to edit the default configuration, enabling the
    execution of arbitrary commands. (CVE-2022-47506)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2023-23836
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fb1d8ab");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-38111
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?62a2897f");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-47503
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e16b39cc");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-47504
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?abb3dfff");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-47506
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c52761b4");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-47507
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?55c33818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SolarWinds Platform version 2023.1 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23836");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-47506");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/15");

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
  { 'fixed_version' : '2023.1', 'equal' : '2022.4.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
