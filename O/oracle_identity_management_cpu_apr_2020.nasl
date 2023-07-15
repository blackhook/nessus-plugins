#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(136284);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2018-15756", "CVE-2019-0222");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Identity Manager Connector Multiple Vulnerabilities (April 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by a remote
security vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing the April 2020 Critical Patch Update for
Oracle Identity Manager Connector. It is, therefore, affected by multiple vulnerabilities:

 - Vulnerability in the Identity Manager Connector product of Oracle Fusion Middleware 
 (component: General (Apache ActiveMQ)). The supported version that is affected is 9.0. Easily exploitable 
 vulnerability allows unauthenticated attacker with network access via HTTP to compromise Identity Manager Connector. 
 Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable 
 crash (complete DOS) of Identity Manager Connector. (CVE-2019-0222)

 - Vulnerability in the Identity Manager Connector product of Oracle Fusion Middleware (component: LDAP Gateway 
 (Spring Framework)). The supported version that is affected is 9.0. Easily exploitable vulnerability allows 
 unauthenticated attacker with network access via HTTP to compromise Identity Manager Connector. Successful attacks of 
 this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of
 Identity Manager Connector. (CVE-2018-15756)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2020 Oracle
Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0222");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:identity_manager");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_identity_management_installed.nbin");
  script_require_keys("installed_sw/Oracle Identity Manager");

  exit(0);
}
include('vcf.inc');

appname = 'Oracle Identity Manager';

app_info = vcf::get_app_info(app:appname);
 
constraints = [
  {'min_version': '9.0', 'fixed_version': '9.1'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_WARNING);