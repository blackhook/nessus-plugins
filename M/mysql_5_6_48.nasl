##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(135699);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-2752",
    "CVE-2020-2763",
    "CVE-2020-2780",
    "CVE-2020-2804",
    "CVE-2020-2812",
    "CVE-2020-2814",
    "CVE-2020-2922",
    "CVE-2021-2007"
  );
  script_xref(name:"IAVA", value:"2020-A-0143");
  script_xref(name:"IAVA", value:"2021-A-0038");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MySQL 5.6.x < 5.6.48 Multiple Vulnerabilities (Apr 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to 5.6.48. It is, therefore, affected by multiple
of service vulnerabilities, including the following, as noted in the April 2020 Critical Patch Update 
advisory:

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Memcached). Supported versions
  that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Difficult to exploit
  vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2804)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: InnoDB). Supported versions that are
  affected are 5.6.47 and prior, 5.7.28 and prior and 8.0.18 and prior. Easily exploitable vulnerability allows
  high privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
  attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server. (CVE-2020-2814)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
  versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
  vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL
  Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2812)


Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://www.oracle.com/security-alerts/cpuapr2020.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b68cc3b");
  # https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f5cff95");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.48 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2007");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/17");

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

var constraints = [{ 'min_version' : '5.6.0', 'fixed_version' : '5.6.48'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);