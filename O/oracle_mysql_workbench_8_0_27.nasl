#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154655);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-3518", "CVE-2021-3712", "CVE-2021-20227");
  script_xref(name:"IAVA", value:"2021-A-0487");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Oracle MySQL Workbench < 8.0.27 Multiple Vulnerabilities (Oct 2021)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle MySQL Workbench installed on the remote Windows host is prior to 8.0.27. It is, therefore, 
affected by multiple vulnerabilities as referenced in the advisory.

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: MySQL Workbench (OpenSSL)). Supported 
    versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows unauthenticated 
    attacker with network access via MySQL Workbench to compromise MySQL Workbench.  Successful attacks of this 
    vulnerability can result in unauthorized access to critical data or complete access to all MySQL Workbench 
    accessible data and unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL 
    Workbench. (CVE-2021-3712)

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: MySQL Workbench (libxml2)). Supported 
    versions that are affected are 8.0.26 and prior. Easily exploitable vulnerability allows unauthenticated attacker 
    with network access via MySQL Workbench to compromise MySQL Workbench.  Successful attacks require human interaction 
    from a person other than the attacker. Successful attacks of this vulnerability can result in takeover of MySQL 
    Workbench. (CVE-2021-3518)

  - Vulnerability in the MySQL Workbench product of Oracle MySQL (component: MySQL Workbench (OpenSSL)). Supported 
    versions that are affected are 8.0.26 and prior. Difficult to exploit vulnerability allows unauthenticated attacker 
    with network access via MySQL Workbench to compromise MySQL Workbench. Successful attacks of this vulnerability 
    can result in unauthorized access to critical data or complete access to all MySQL Workbench accessible data and 
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Workbench

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle MySQL Workbench version 8.0.27 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3518");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql_workbench");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql_workbench");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_workbench_win_installed.nbin");
  script_require_keys("installed_sw/MySQL Workbench");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'MySQL Workbench');

var constraints = [
  { 'fixed_version' : '8.0.27' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);