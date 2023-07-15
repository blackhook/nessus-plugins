#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(124159);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-1547",
    "CVE-2019-2632",
    "CVE-2019-1559",
    "CVE-2019-2628",
    "CVE-2019-2566",
    "CVE-2019-2581",
    "CVE-2019-2683",
    "CVE-2019-2592",
    "CVE-2019-2627",
    "CVE-2019-2614",
    "CVE-2019-2755"
  );
  script_bugtraq_id(107174, 107924, 107927);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MySQL 5.7.x < 5.7.26 Multiple Vulnerabilities (Apr 2019 CPU) (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.26. It is, therefore, affected by multiple vulnerabilities,
including three of the top vulnerabilities below, as noted in the
April 2019 Critical Patch Update advisory:

  - An unspecified vulnerability in MySQL in the
    'Server : Pluggable Auth' subcomponent could allow an
    unauthenticated attacker to gain complete access to all
    MySQL Server accessible data. (CVE-2019-2632)

  - An unspecified vulnerability in the
    'Server: Compiling (OpenSSL)' subcomponent could allow
    an unauthenticated attacker to gain complete access to
    all MySQL Server accessible data. (CVE-2019-1559)

  - An unspecified vulnerability in the 'InnoDB'
    subcomponent could allow a high privileged attacker to
    cause the server to hang or to, via a frequently
    repeatable crash, cause a complete denial of service.
    (CVE-2019-2628)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-27.html");
  # https://www.oracle.com/technetwork/security-advisory/cpuapr2019-5072813.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e6252734");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.26 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}
include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

var constraints = [{ 'min_version' : '5.7.0', 'fixed_version' : '5.7.26'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
