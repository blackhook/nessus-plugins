#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160377);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id(
    "CVE-2021-3518",
    "CVE-2021-44832",
    "CVE-2022-21469",
    "CVE-2022-23305"
  );
  script_xref(name:"IAVA", value:"2021-A-0573");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 and 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by
multiple vulnerabilities as referenced in the April 2022 CPU advisory.

  - Vulnerability in the Oracle Management Service component (Apache Log4j) of the Enterprise Manager
    Base Platform. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via HTTP to compromise and take over the Enterprise Manager Base Platform. (CVE-2022-23305)

  - Vulnerability in the Enterprise Manager Install component (libxml2) of the Enterprise Manager
    Base Platform. Easily exploitable vulnerability allows unauthenticated attacker with network access
    via HTTP to compromise and take over the Enterprise Manager Base Platform. (CVE-2021-3518)

  - Vulnerability in the Enterprise Manager Install component (Apache Log4j) of the Enterprise Manager
    Base Platform. Difficult to exploit vulnerability allows high privileged attacker with network access
    via HTTP to compromise and take over the Enterprise Manager Base Platform. (CVE-2021-44832)

  - Vulnerability in the UI Framework component of the Enterprise Manager Base Platform. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    the Enterprise Manager Base Platform. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Enterprise Manager Base Platform, attacks may
    significantly impact additional products (scope change). Successful attacks of this vulnerability
    can result in unauthorized update, insert or delete access to some of Enterprise Manager Base Platform
    accessible data. (CVE-2022-21469)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

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
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.15', 'fixed_display': '13.4.0.15 (Patch 33726878)'},
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.5', 'fixed_display': '13.5.0.5 (Patch 33731694)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
