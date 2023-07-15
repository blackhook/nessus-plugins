##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163405);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/30");

  script_cve_id("CVE-2022-21516", "CVE-2022-21536", "CVE-2022-29577");
  script_xref(name:"IAVA", value:"2022-A-0286");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Jul 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 and 13.5.0.0 versions of Enterprise Manager Base Platform installed on the remote host are affected by
multiple vulnerabilities as referenced in the July 2022 CPU advisory.

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Enterprise Manager Install). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise
    Enterprise Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized
    update, insert or delete access to some of Enterprise Manager Base Platform accessible data as well as
    unauthorized read access to a subset of Enterprise Manager Base Platform accessible data and unauthorized
    ability to cause a partial denial of service (partial DOS) of Enterprise Manager Base Platform. 
    (CVE-2022-21516)
    
  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Policy Framework). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. Difficult to exploit
    vulnerability allows unauthenticated attacker with network access via HTTP to compromise Enterprise
    Manager Base Platform. Successful attacks of this vulnerability can result in takeover of Enterprise
    Manager Base Platform. (CVE-2022-21536)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component: 
    Enterprise Manager Install (AntiSamy)). Supported versions that are affected are 13.4.0.0 and 13.5.0.0. 
    Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP to 
    compromise Enterprise Manager Base Platform. Successful attacks require human interaction from a person
    other than the attacker and while the vulnerability is in Enterprise Manager Base Platform, attacks may 
    significantly impact additional products (scope change). Successful attacks of this vulnerability can 
    result in unauthorized update, insert or delete access to some of Enterprise Manager Base Platform 
    accessible data as well as unauthorized read access to a subset of Enterprise Manager Base Platform 
    accessible data. (CVE-2022-29577)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpujul2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

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
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.17' },
  { 'min_version' : '13.5.0.0', 'fixed_version' : '13.5.0.8' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
