#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174743);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/26");

  script_cve_id(
    "CVE-2018-1000656",
    "CVE-2019-10086",
    "CVE-2021-27568",
    "CVE-2021-4048",
    "CVE-2021-40690",
    "CVE-2022-1587",
    "CVE-2022-31160",
    "CVE-2022-32215",
    "CVE-2022-37434",
    "CVE-2022-42003",
    "CVE-2022-42889",
    "CVE-2023-21910",
    "CVE-2023-21952",
    "CVE-2023-21965"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Business Intelligence Enterprise Edition (OAS) (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of Oracle Business Intelligence Enterprise Edition (OBIEE) (OAS) installed
on the remote host are affected by multiple vulnerabilities as referenced in the April 2023 CPU advisory.

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Server (Apache Commons BeanUtils)). The supported version that is affected is 
    6.4.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP 
    to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability 
    can result in unauthorized update, insert or delete access to some of Oracle Business Intelligence 
    Enterprise Edition accessible data as well as unauthorized read access to a subset of Oracle Business 
    Intelligence Enterprise Edition accessible data and unauthorized ability to cause a partial denial of 
    service (partial DOS) of Oracle Business Intelligence Enterprise Edition. (CVE-2019-10086)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: Analytics Server (zlib)). The supported version that is affected is 6.4.0.0.0. Easily 
    exploitable vulnerability allows unauthenticated attacker with network access via HTTP to compromise 
    Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability can result in 
    takeover of Oracle Business Intelligence Enterprise Edition. (CVE-2022-37434)

  - Vulnerability in the Oracle Business Intelligence Enterprise Edition product of Oracle Analytics 
    (component: BI Application Archive (Apache Commons Text)). The supported version that is affected is 
    6.4.0.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP 
    to compromise Oracle Business Intelligence Enterprise Edition. Successful attacks of this vulnerability 
    can result in takeover of Oracle Business Intelligence Enterprise Edition. (CVE-2022-42889)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10086");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:business_intelligence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_business_intelligence_enterprise_edition_installed.nbin");
  script_require_keys("installed_sw/Oracle Business Intelligence Enterprise Edition");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Oracle Business Intelligence Enterprise Edition');

var constraints = [
  {'min_version': '12.2.6.4.0', 'fixed_version': '12.2.6.4.230404', 'fixed_display': '12.2.6.4.230404 patch: 35253109'}
];

vcf::check_version_and_report(app_info: app_info, constraints:constraints, severity:SECURITY_HOLE);