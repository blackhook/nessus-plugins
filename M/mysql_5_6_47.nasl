#
# (C) Tenable Network Security, Inc.
#

#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(132956);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id("CVE-2019-1547", "CVE-2020-2574", "CVE-2020-2579");
  script_xref(name:"IAVA", value:"2020-A-0021-S");

  script_name(english:"MySQL 5.6.x < 5.6.47 Multiple Vulnerabilities (Jan 2020 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to 5.6.47. It is, therefore, affected by multiple
vulnerabilities, including three of the top vulnerabilities below, as noted in the January 2020 Critical Patch Update
advisory:
  - Unspecified vulnerability in the optimizer component of Oracle MySQL Server. An authenticated, remote attacker
  could exploit this issue, to compromise the availability of the application (CVE-2020-2579).

  - Unspecified vulnerabilities in the MySQL client component of Oracle MySQL Server. An unauthenticated, remote
  attacker could exploit these issues, to compromise the availability of the application (CVE-2020-2574).

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (OpenSSL)).
  Supported versions that are affected are 5.6.46 and prior, 5.7.26 and prior and 8.0.18 and prior. This difficult to exploit
  vulnerability allows low privileged attacker with logon to the infrastructure where MySQL Server executes to
  compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized access to
  critical data or complete access to all MySQL Server accessible data (CVE-2019-1547).

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-47.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c067f29");
  # https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-47.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c067f29");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.47 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1547");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies(
    "mysql_version.nasl",
    "mysql_login.nasl",
    "mysql_version_local.nasl",
    "mysql_win_installed.nbin",
    "macosx_mysql_installed.nbin"
  );
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

var constraints = [{ 'min_version' : '5.6.0', 'fixed_version' : '5.6.47'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);