#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159930);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2021-2351", "CVE-2021-40438", "CVE-2021-44832");
  script_xref(name:"IAVA", value:"2022-A-0165");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");

  script_name(english:"Oracle Enterprise Manager Ops Center (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 12.4.0.0 versions of Enterprise Manager Ops Center installed on the remote host are affected by multiple
vulnerabilities as referenced in the April 2022 CPU advisory.

  - Vulnerability in the Oracle Secure Global Desktop product of Oracle Virtualization (component: Web Server
    (Apache HTTP Server)). The supported version that is affected is 5.6. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle Secure Global Desktop.
    While the vulnerability is in Oracle Secure Global Desktop, attacks may significantly impact additional
    products (scope change). Successful attacks of this vulnerability can result in takeover of Oracle Secure
    Global Desktop. (CVE-2021-40438)

  - Vulnerability in the Oracle StorageTek ACSLS product of Oracle Systems (component: Software (JDBC)). The
    supported version that is affected is 8.5.1. Difficult to exploit vulnerability allows unauthenticated
    attacker with network access via Oracle Net to compromise Oracle StorageTek ACSLS. Successful attacks
    require human interaction from a person other than the attacker and while the vulnerability is in Oracle
    StorageTek ACSLS, attacks may significantly impact additional products (scope change). Successful attacks
    of this vulnerability can result in takeover of Oracle StorageTek ACSLS. (CVE-2021-2351)

  - Vulnerability in the Oracle WebCenter Sites product of Oracle Fusion Middleware (component: Advanced UI
    (Apache Log4j)). Supported versions that are affected are 12.2.1.3.0 and 12.2.1.4.0. Difficult to exploit
    vulnerability allows high privileged attacker with network access via HTTP to compromise Oracle WebCenter
    Sites. Successful attacks of this vulnerability can result in takeover of Oracle WebCenter Sites. CVSS 3.1
    Base Score 6.6 (Confidentiality, Integrity and Availability impacts). (CVE-2021-44832)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-40438");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager_ops_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_ops_center_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Ops Center");

  exit(0);
}

include('vcf_extras_oracle_em_ops_center.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var constraints = [
  {'min_version': '12.4.0.0', 'max_version': '12.4.0.9999', 'uce_patch': '34037334'}
];

var app_info = vcf::oracle_em_ops_center::get_app_info();

vcf::oracle_em_ops_center::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
