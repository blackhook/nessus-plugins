#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167838);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2013-1502",
    "CVE-2013-1511",
    "CVE-2013-1532",
    "CVE-2013-1544",
    "CVE-2013-2375",
    "CVE-2013-2376",
    "CVE-2013-2389",
    "CVE-2013-2391",
    "CVE-2013-2392",
    "CVE-2013-3794",
    "CVE-2013-3801",
    "CVE-2013-3805",
    "CVE-2013-3808"
  );

  script_name(english:"MariaDB 5.5.0 < 5.5.31 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.31. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-5-5-31-release-notes advisory.

  - Unspecified vulnerability in Oracle MySQL 5.5.30 and earlier and 5.6.9 and earlier allows local users to
    affect availability via unknown vectors related to Server Partition. (CVE-2013-1502)

  - Unspecified vulnerability in Oracle MySQL 5.5.30 and earlier and 5.6.10 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to InnoDB. (CVE-2013-1511)

  - Unspecified vulnerability in Oracle MySQL 5.1.68 and earlier, 5.5.30 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect availability via unknown vectors related to Information
    Schema. (CVE-2013-1532)

  - Unspecified vulnerability in Oracle MySQL 5.1.68 and earlier, 5.5.30 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect availability via unknown vectors related to Data Manipulation
    Language. (CVE-2013-1544)

  - Unspecified vulnerability in Oracle MySQL 5.1.68 and earlier, 5.5.30 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect confidentiality, integrity, and availability via unknown
    vectors. (CVE-2013-2375)

  - Unspecified vulnerability in Oracle MySQL 5.5.30 and earlier and 5.6.10 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Stored Procedure.
    (CVE-2013-2376)

  - Unspecified vulnerability in Oracle MySQL 5.1.68 and earlier, 5.5.30 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect availability via unknown vectors related to InnoDB.
    (CVE-2013-2389)

  - Unspecified vulnerability in Oracle MySQL 5.1.68 and earlier, 5.5.30 and earlier, and 5.6.10 and earlier
    allows local users to affect confidentiality and integrity via unknown vectors related to Server Install.
    (CVE-2013-2391)

  - Unspecified vulnerability in Oracle MySQL 5.1.68 and earlier, 5.5.30 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect availability via unknown vectors related to Server Optimizer.
    (CVE-2013-2392)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.30 and earlier and 5.6.10
    allows remote authenticated users to affect availability via unknown vectors related to Server Partition.
    (CVE-2013-3794)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.30 and earlier and 5.6.10
    allows remote authenticated users to affect availability via unknown vectors related to Server Options.
    (CVE-2013-3801)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.30 and earlier and 5.6.10
    allows remote authenticated users to affect availability via unknown vectors related to Prepared
    Statements. (CVE-2013-3805)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.68 and earlier, 5.5.30 and
    earlier, and 5.6.10 allows remote authenticated users to affect availability via unknown vectors related
    to Server Options. (CVE-2013-3808)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5-5-31-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.31 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2375");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-3808");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mariadb_nix_installed.nbin", "mariadb_win_installed.nbin");
  script_require_keys("installed_sw/MariaDB");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'MariaDB');

if (!(app_info.local) && report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN, 'MariaDB');

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '5.5', 'fixed_version' : '5.5.31' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
