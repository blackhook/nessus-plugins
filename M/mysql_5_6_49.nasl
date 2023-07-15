#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138571);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-1967",
    "CVE-2020-14539",
    "CVE-2020-14550",
    "CVE-2020-14559"
  );
  script_xref(name:"IAVA", value:"2020-A-0321");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"MySQL 5.6.x < 5.6.49 Multiple Vulnerabilities (Jul 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to and including 5.6.48. It is, therefore, affected by
multiple vulnerabilities, including the following, as noted in the July 2020 Critical Patch Update 
advisory:

  -  A vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions
  that are affected are 5.6.48 and prior, 5.7.30 and prior and 8.0.20 and prior. Easily exploitable
  vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2020-14539)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
  affected are 5.6.48 and prior, 5.7.30 and prior and 8.0.20 and prior. Difficult to exploit vulnerability allows
  low privileged attacker with network access via multiple protocols to compromise MySQL Client. Successful
  attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Client. (CVE-2020-14550)

  - Vulnerability in the MySQL Connectors product of Oracle MySQL (component: Connector/C++ (OpenSSL)).
  Supported versions that are affected are 8.0.20 and prior. Easily exploitable vulnerability allows unauthenticated
  attacker with network access via TLS to compromise MySQL Connectors. Successful attacks of this vulnerability can
  result in unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL
  Connectors. (CVE-2020-1967)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpujul2020.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dc7b9bd1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.49 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14559");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/17");

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

var constraints = [{ 'min_version' : '5.6.0', 'fixed_version' : '5.6.49'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);