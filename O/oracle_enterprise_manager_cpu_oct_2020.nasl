#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(141809);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-2897", "CVE-2020-1954", "CVE-2020-1967");
  script_xref(name:"IAVA", value:"2020-A-0481");
  script_xref(name:"IAVA", value:"2021-A-0328");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle Enterprise Manager Cloud Control (Oct 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 13.3.0.0, 13.3.1.0 and 13.4.0.0 versions of Enterprise Manager Base Platform installed on the remote host are
affected by multiple vulnerabilities as referenced in the October 2020 CPU advisory.

  - Vulnerability in the Enterprise Manager for Storage Management product of Oracle Enterprise Manager 
    (component: Privilege Management (OpenSSL)). Supported versions that are affected are 13.3.0.0 and 
    13.4.0.0. Easily exploitable vulnerability allows unauthenticated attacker with network access via 
    HTTPS to compromise Enterprise Manager for Storage Management. Successful attacks of this 
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash 
    (complete DOS) of Enterprise Manager for Storage Management. (CVE-2020-1967)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Event Management). Supported versions that are affected are 13.3.0.0 and 13.4.0.0. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTP to compromise Enterprise Manager
    Base Platform. While the vulnerability is in Enterprise Manager Base Platform, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of Enterprise Manager Base Platform accessible data as well as
    unauthorized read access to a subset of Enterprise Manager Base Platform accessible data. (CVE-2019-2897)

  - Vulnerability in the Enterprise Manager Base Platform product of Oracle Enterprise Manager (component:
    Connector Framework (Apache CXF)). The supported version that is affected is 13.2.1.0. Difficult to
    exploit vulnerability allows unauthenticated attacker with access to the physical communication segment
    attached to the hardware where the Enterprise Manager Base Platform executes to compromise Enterprise
    Manager Base Platform. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all Enterprise Manager Base Platform accessible data. (CVE-2020-1954)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2020.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2020 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2897");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_enterprise_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Enterprise Manager Cloud Control");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'Oracle Enterprise Manager Cloud Control');

constraints = [
  { 'min_version' : '13.3.0.0', 'fixed_version' : '13.3.0.0.201020' , 'fixed_display': '13.3.0.0.201020 (Patch 31899771)'},
  { 'min_version' : '13.3.1.0', 'fixed_version' : '13.3.1.0.201031' , 'fixed_display': '13.3.1.0.201031 (Patch 32019093)'},
  { 'min_version' : '13.4.0.0', 'fixed_version' : '13.4.0.8',  'fixed_display': '13.4.0.8 (Patch 32071974)'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
