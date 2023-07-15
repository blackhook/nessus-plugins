#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(170202);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/23");

  script_cve_id("CVE-2021-3518", "CVE-2021-26691");
  script_xref(name:"IAVA", value:"2021-A-0482");

  script_name(english:"Oracle Enterprise Manager Ops Center UCE Patches (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.4.0.0 versions of Enterprise Manager Ops Center installed on the remote host are affected by multiple
vulnerabilities as referenced in the October 2021 CPU advisory.

  - Vulnerability in the Enterprise Manager Ops Center product of Oracle Enterprise Manager (component: 
    Networking (Apache HTTP Server)). The supported version that is affected is 12.4.0.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Enterprise
    Manager Ops Center. Successful attacks of this vulnerability can result in takeover of Enterprise
    Manager Ops Center. (CVE-2021-26691)

  - Vulnerability in the Enterprise Manager Ops Center product of Oracle Enterprise Manager (component: Guest
    Management (libxml2)). The supported version that is affected is 12.4.0.0. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Enterprise
    Manager Ops Center. Successful attacks require human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in takeover of Enterprise Manager Ops Center.
    (CVE-2021-3518)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26691");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

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
  {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'uce_patch': '33352383'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
