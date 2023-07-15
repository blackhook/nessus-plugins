#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174528);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2022-31160", "CVE-2022-45143", "CVE-2023-0215");
  script_xref(name:"IAVA", value:"2023-A-0212");

  script_name(english:"Oracle MySQL Enterprise Monitor (Apr 2023 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2023 CPU advisory.

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: Workbench (OpenSSL)). Supported
    versions that are affected are 8.0.32 and prior. Easily exploitable vulnerability allows unauthenticated
    attacker with network access via MySQL Workbench to compromise MySQL Workbench. Successful attacks of this
    vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
    DOS) of MySQL Workbench. (CVE-2023-0215)

  - Vulnerability in the Oracle SD-WAN Edge product of Oracle Communications (component: Internal tools
    (Apache Tomcat)). The supported version that is affected is 9.1.1.4.0. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via HTTP to compromise Oracle SD-WAN Edge. Successful
    attacks of this vulnerability can result in unauthorized creation, deletion or modification access to
    critical data or all Oracle SD-WAN Edge accessible data. (CVE-2022-45143)

  - Vulnerability in the Oracle WebLogic Server product of Oracle Fusion Middleware (component: Console
    (jQueryUI)). Supported versions that are affected are 12.2.1.4.0 and 14.1.1.0.0. Difficult to exploit
    vulnerability allows high privileged attacker with logon to the infrastructure where Oracle WebLogic
    Server executes to compromise Oracle WebLogic Server. While the vulnerability is in Oracle WebLogic
    Server, attacks may significantly impact additional products (scope change). Successful attacks of this
    vulnerability can result in unauthorized update, insert or delete access to some of Oracle WebLogic Server
    accessible data as well as unauthorized read access to a subset of Oracle WebLogic Server accessible data.
    (CVE-2022-31160)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2023cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2023.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2023 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-45143");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [{ 'min_version' : '8.0', 'fixed_version' : '8.0.34' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
