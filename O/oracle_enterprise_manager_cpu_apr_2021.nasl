#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148895);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-17195",
    "CVE-2020-10878",
    "CVE-2020-11994",
    "CVE-2021-2053"
  );
  script_xref(name:"IAVA", value:"2021-A-0191");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.4.0.0 version of Enterprise Manager Base Platform installed on the remote host is
affected by multiple vulnerabilities as referenced in the April 2021 CPU advisory.

  - Vulnerability in the Enterprise Manager for Virtualization product of Oracle Enterprise Manager 
    (component: Administration operations (Apache Commons BeanUtils)). The supported version that is affected 
    is 13.4.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via HTTP 
    to compromise Enterprise Manager for Virtualization. Successful attacks of this vulnerability can result 
    in unauthorized update, insert or delete access to some of Enterprise Manager for Virtualization accessible 
    data as well as unauthorized read access to a subset of Enterprise Manager for Virtualization accessible data 
    and unauthorized ability to cause a partial denial of service (partial DOS) of Enterprise Manager for 
    Virtualization. (CVE-2019-10086)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component: 
    EM on Market Place (Perl)). The supported version that is affected is 13.4.0.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Enterprise Manager Base Platform. 
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable 
    crash (complete DOS) of Enterprise Manager Base Platform as well as unauthorized update, insert or delete access to 
    some of Enterprise Manager Base Platform accessible data and unauthorized read access to a subset of Enterprise 
    Manager Base Platform accessible data. (CVE-2020-10878)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component: Reporting 
    Framework (Apache Camel)). The supported version that is affected is 13.4.0.0. Easily exploitable vulnerability 
    allows unauthenticated attacker with network access via HTTP to compromise Enterprise Manager Base Platform. 
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete access 
    to all Enterprise Manager Base Platform accessible data. (CVE-2020-11994)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component: UI Framework).
    The supported version that is affected is 13.4.0.0. Easily exploitable vulnerability allows unauthenticated attacker 
    with network access via HTTP to compromise Enterprise Manager Base Platform. Successful attacks require human 
    interaction from a person other than the attacker and while the vulnerability is in Enterprise Manager Base Platform, 
    attacks may significantly impact additional products. Successful attacks of this vulnerability can result in unauthorized 
    update, insert or delete access to some of Enterprise Manager Base Platform accessible data as well as unauthorized 
    read access to a subset of Enterprise Manager Base Platform accessible data. (CVE-2021-2053)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17195");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

constraints = [
    { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.10' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);


