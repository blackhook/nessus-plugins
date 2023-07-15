#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170273);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/24");

  script_cve_id("CVE-2021-2351", "CVE-2021-3177");
  script_xref(name:"IAVA", value:"2021-A-0482");
  script_xref(name:"IAVA", value:"2022-A-0036");
  script_xref(name:"IAVA", value:"2022-A-0165");

  script_name(english:"Oracle Enterprise Manager Ops Center UI and Other Patches (January 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.4.0.0 versions of Enterprise Manager Ops Center installed on the remote host are affected by multiple
vulnerabilities as referenced in the January 2022 CPU advisory.

  - Vulnerability in the Enterprise Manager Ops Center product of Oracle Enterprise Manager (component:
    Networking (JDBC)). The supported version that is affected is 12.4.0.0. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via Oracle Net to compromise Enterprise Manager Ops
    Center. Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in Enterprise Manager Ops Center, attacks may significantly impact additional products
    (scope change). Successful attacks of this vulnerability can result in takeover of Enterprise Manager Ops
    Center. (CVE-2021-2351)

  - Vulnerability in the Enterprise Manager Ops Center product of Oracle Enterprise Manager (component:
    Networking (Python)). The supported version that is affected is 12.4.0.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Enterprise Manager Ops Center.
    Successful attacks of this vulnerability can result in takeover of Enterprise Manager Ops Center.
    (CVE-2021-3177)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the January 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var constraints = [
  {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'ui_patch': '33701457'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);