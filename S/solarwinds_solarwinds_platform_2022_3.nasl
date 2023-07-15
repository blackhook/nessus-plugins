#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165521);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/21");

  script_cve_id("CVE-2022-36961", "CVE-2022-36965");
  script_xref(name:"IAVA", value:"2022-A-0404-S");

  script_name(english:"SolarWinds Orion Platform < 2022.3 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The version of SolarWinds Orion Platform installed on the remote host is prior to 2022.3. It is, therefore, affected by
multiple vulnerabilities as referenced in the solarwinds_platform_2022_3 advisory.

  - A vulnerable component of Orion Platform was vulnerable to SQL Injection, an authenticated attacker could
    leverage this for privilege escalation or remote code execution. (CVE-2022-36961)

  - Insufficient sanitization of inputs in QoE application input field could lead to stored and Dom based XSS
    attack. This issue is fixed and released in SolarWinds Platform (2022.3.0). (CVE-2022-36965)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-36965
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c368ddb");
  # https://www.solarwinds.com/trust-center/security-advisories/cve-2022-36961
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bae7ff74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Orion Platform version 2022.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36961");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/28");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:solarwinds:orion_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("solarwinds_orion_npm_detect.nasl", "solarwinds_orion_installed.nbin");
  script_require_keys("installed_sw/SolarWinds Orion Core");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::solarwinds_orion::initialize();
var app_info = vcf::solarwinds_orion::combined_get_app_info();

var constraints = [
  { 'fixed_version' : '2022.3' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
