#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166323);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-21623");
  script_xref(name:"IAVA", value:"2022-A-0426");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 and 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by a
vulnerability as referenced in the October 2022 CPU advisory.

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Application Config Console). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized
    creation, deletion or modification access to critical data or all Enterprise Manager Base Platform
    accessible data. (CVE-2022-21623)
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21623");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

var constraints = [
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.18', 'fixed_display': '13.4.0.18 (Patch 34519159)' },
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.10', 'fixed_display': '13.5.0.10 (Patch 34611813)' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
