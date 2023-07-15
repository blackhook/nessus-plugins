#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159917);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id(
    "CVE-2021-41184",
    "CVE-2021-42340",
    "CVE-2021-44832",
    "CVE-2022-0778",
    "CVE-2022-22965",
    "CVE-2022-22968",
    "CVE-2022-23181",
    "CVE-2022-23305"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/25");
  script_xref(name:"IAVA", value:"2022-A-0168-S");

  script_name(english:"Oracle MySQL Enterprise Monitor (Apr 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the April 2022 CPU advisory.

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Apache Log4j)). Supported versions that are affected are 8.0.29 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Enterprise Monitor. Successful attacks of this vulnerability can result in takeover of MySQL
    Enterprise Monitor. (CVE-2022-23305)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Spring Framework)). Supported versions that are affected are 8.0.29 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Enterprise Monitor. Successful attacks of this vulnerability can result in takeover of MySQL
    Enterprise Monitor. (CVE-2022-22965)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Apache Tomcat)). Supported versions that are affected are 8.0.29 and prior. Easily exploitable
    vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise
    MySQL Enterprise Monitor. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Enterprise Monitor. (CVE-2021-42340)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Spring Framework)). Supported versions that are affected are 8.0.29 and prior. The patterns for 
    disallowedFields on a DataBinder are case sensitive which means a field is not effectively protected unless it is 
    listed with both upper and lower case for the first character of the field, including upper and lower case for the
     first character of all nested fields within the property path. (CVE-2022-22968)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuapr2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the April 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-44832");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-23305");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Spring Framework Class property RCE (Spring4Shell)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.30' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
