#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151978);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id("CVE-2020-2555", "CVE-2021-2358");
  script_xref(name:"IAVA", value:"2021-A-0326");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0129");

  script_name(english:"Oracle Access Manager Multiple Vulnerabilities (Jul 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a Single Sign On (SSO) application installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle Access Manager installed on the remote host is affected by the following vulnerabilities as noted in
the July 2021 CPU advisory :
  
  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Rest interfaces
    for Access Mgr). The supported version that is affected is 11.1.2.3.0. Easily exploitable vulnerability
    allows high privileged attacker with network access via HTTPS to compromise Oracle Access Manager.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all Oracle Access Manager accessible data. (CVE-2021-2358)

  - Vulnerability in the Oracle Access Manager product of Oracle Fusion Middleware (component: Installation
    Component (Oracle Coherence)). The supported version that is affected is 11.1.2.3.0. Difficult to exploit
    vulnerability allows high privileged attacker with access to the physical communication segment attached
    to the hardware where the Oracle Access Manager executes to compromise Oracle Access Manager. Successful
    attacks of this vulnerability can result in unauthorized update, insert or delete access to some of Oracle
    Access Manager accessible data as well as unauthorized read access to a subset of Oracle Access Manager
    accessible data. (CVE-2020-2555)


Note that Nessus has not attempted to exploit these issues but has instead relied only on the application's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patches according to the July 2021 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2555");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'WebLogic Server Deserialization RCE - BadAttributeValueExpException');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:fusion_middleware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:access_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("oracle_access_manager_installed.nbin");
  script_require_keys("installed_sw/Oracle Access Manager");

  exit(0);
}

include('vcf.inc');

var appname = 'Oracle Access Manager';

var app_info = vcf::get_app_info(app:appname);

var constraints = [
  {'min_version': '11.1.2.3', 'fixed_version': '11.1.2.3.210611'}
];
vcf::check_version_and_report(app_info: app_info, constraints: constraints, severity: SECURITY_HOLE);
