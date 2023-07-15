#
# (C) Tenable Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(130025);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/21");

  script_cve_id(
    "CVE-2019-2910",
    "CVE-2019-2911",
    "CVE-2019-2922",
    "CVE-2019-2923",
    "CVE-2019-2924",
    "CVE-2019-2974"
  );
  script_xref(name:"IAVA", value:"2019-A-0383-S");

  script_name(english:"MySQL 5.6.x < 5.6.46 Multiple Vulnerabilities (Oct 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to 5.6.46. It is, therefore, affected by multiple
vulnerabilities, including three of the top vulnerabilities below, as noted in the October 2019 Critical Patch Update
advisory:
  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Easily exploitable
  vulnerability allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
  crash (complete DOS) of MySQL Server. (CVE-2019-2794)

  - Vulnerabilities in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption). Easily
  exploitable vulnerabilities allow unauthenticated attackers with network access via multiple protocols to compromise
  MySQL Server. Successful exploitation of these vulnerabilities can result in unauthorized read access to a subset of
  MySQL Server accessible data. (CVE-2019-2923, CVE-2019-2924)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-46.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1812e93");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b370bc74");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.46 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2924");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var constraints = [{ 'min_version' : '5.6.0', 'fixed_version' : '5.6.46'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);