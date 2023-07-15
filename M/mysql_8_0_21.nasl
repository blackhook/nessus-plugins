##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138560);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-1551",
    "CVE-2020-1967",
    "CVE-2020-5258",
    "CVE-2020-14539",
    "CVE-2020-14540",
    "CVE-2020-14547",
    "CVE-2020-14550",
    "CVE-2020-14553",
    "CVE-2020-14559",
    "CVE-2020-14568",
    "CVE-2020-14575",
    "CVE-2020-14576",
    "CVE-2020-14586",
    "CVE-2020-14591",
    "CVE-2020-14597",
    "CVE-2020-14614",
    "CVE-2020-14619",
    "CVE-2020-14620",
    "CVE-2020-14623",
    "CVE-2020-14624",
    "CVE-2020-14631",
    "CVE-2020-14632",
    "CVE-2020-14633",
    "CVE-2020-14634",
    "CVE-2020-14641",
    "CVE-2020-14643",
    "CVE-2020-14651",
    "CVE-2020-14654",
    "CVE-2020-14656",
    "CVE-2020-14663",
    "CVE-2020-14678",
    "CVE-2020-14680",
    "CVE-2020-14697",
    "CVE-2020-14702",
    "CVE-2020-14725",
    "CVE-2020-14799",
    "CVE-2021-1998",
    "CVE-2021-2012",
    "CVE-2021-2020"
  );
  script_xref(name:"IAVA", value:"2020-A-0321");
  script_xref(name:"IAVA", value:"2020-A-0473-S");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"MySQL 8.0.x < 8.0.21 Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to and including 8.0.20. It is, therefore, affected by multiple
vulnerabilities, including the following, as noted in the July 2020 Critical Patch Update advisory:

  -  Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Privileges).
  Supported versions that are affected are 8.0.20 and prior. Easily exploitable vulnerability allows high privileged
  attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
  vulnerability can result in takeover of MySQL Server. (CVE-2020-14697, CVE-2020-14678)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions
  that are affected are 8.0.20 and prior. Easily exploitable vulnerability allows low privileged attacker with
  network access via multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-14680)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Roles). Supported
  versions that are affected are 8.0.20 and prior. Easily exploitable vulnerability allows high privileged
  attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of this
  vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
  Server as well as unauthorized update, insert or delete access to some of MySQL Server accessible data. (CVE-2020-14651)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujul2020.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpujan2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.21 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:R/S:C/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14697");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-5258");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.21'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
