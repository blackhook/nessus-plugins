#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154267);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2021-3712",
    "CVE-2021-22112",
    "CVE-2021-22118",
    "CVE-2021-29425",
    "CVE-2021-33037"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle MySQL Enterprise Monitor (Oct 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The 8.0.25 versions of MySQL Enterprise Monitor installed on the remote host are affected by multiple vulnerabilities as
referenced in the October 2021 CPU advisory.

  - Vulnerability in the MySQL Enterprise Monitor product of Oracle MySQL (component: Monitoring: General
    (Spring Security)). Supported versions that are affected are 8.0.25 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via HTTPS to compromise MySQL Enterprise
    Monitor. Successful attacks of this vulnerability can result in takeover of MySQL Enterprise Monitor. (CVE-2021-22112)

  - Vulnerability in the Oracle Retail Predictive Application Server product of Oracle Retail Applications
    (component: RPAS Fusion Client (Spring Framework)). Supported versions that are affected are 14.1.3,
    15.0.3 and 16.0.3. Easily exploitable vulnerability allows low privileged attacker with logon to the
    infrastructure where Oracle Retail Predictive Application Server executes to compromise Oracle Retail
    Predictive Application Server. Successful attacks of this vulnerability can result in takeover of Oracle
    Retail Predictive Application Server. (CVE-2021-22118)

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: MySQL Workbench (OpenSSL)).
    Supported versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via MySQL Workbench to compromise MySQL Workbench. Successful
    attacks of this vulnerability can result in unauthorized access to critical data or complete access to all
    MySQL Workbench accessible data and unauthorized ability to cause a hang or frequently repeatable crash
    (complete DOS) of MySQL Workbench. (CVE-2021-3712)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the October 2021 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-22112");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_enterprise_monitor");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_enterprise_monitor_web_detect.nasl", "oracle_mysql_enterprise_monitor_local_nix_detect.nbin", "oracle_mysql_enterprise_monitor_local_detect.nbin");
  script_require_keys("installed_sw/MySQL Enterprise Monitor");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MySQL Enterprise Monitor');

var constraints = [
  { 'max_version':'8.0.25.99999','fixed_version' : '8.0.27' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
