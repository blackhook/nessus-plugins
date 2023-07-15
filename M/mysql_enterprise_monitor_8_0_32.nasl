#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166325);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id("CVE-2022-2097", "CVE-2022-31129", "CVE-2022-34305");
  script_xref(name:"IAVA", value:"2022-A-0432");

  script_name(english:"Oracle MySQL Enterprise Monitor (Oct 2022 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The versions of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2022 CPU advisory. 
  
  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Moment.js)). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Enterprise
    Monitor. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL Enterprise Monitor. (CVE-2022-31129)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Apache Tomcat)). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Enterprise
    Monitor. Successful attacks require human interaction from a person other than the attacker and while the
    vulnerability is in MySQL Enterprise Monitor, attacks may significantly impact additional products (scope
    change). Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Enterprise Monitor accessible data as well as unauthorized read access to a
    subset of MySQL Enterprise Monitor accessible data. (CVE-2022-34305)

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (OpenSSL)). Supported versions that are affected are 8.0.31 and prior. Easily exploitable vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Enterprise
    Monitor. Successful attacks of this vulnerability can result in unauthorized read access to a subset of
    MySQL Enterprise Monitor accessible data. (CVE-2022-2097)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/docs/tech/security-alerts/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2022 Oracle Critical Patch Update advisory.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2097");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-34305");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin", "macosx_mysql_enterprise_monitor_installed.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'min_version' : '8.0', 'fixed_version' : '8.0.32' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);