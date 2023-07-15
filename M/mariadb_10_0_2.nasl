#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167854);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2012-5614",
    "CVE-2013-1506",
    "CVE-2013-1512",
    "CVE-2013-1521",
    "CVE-2013-1523",
    "CVE-2013-1526",
    "CVE-2013-1552",
    "CVE-2013-1555",
    "CVE-2013-2378"
  );

  script_name(english:"MariaDB 10.0.0 < 10.0.2 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.0.2. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-0-2-release-notes advisory.

  - Oracle MySQL 5.1.67 and earlier and 5.5.29 and earlier, and MariaDB 5.5.28a and possibly other versions,
    allows remote authenticated users to cause a denial of service (mysqld crash) via a SELECT command with an
    UpdateXML command containing XML with a large number of unique, nested elements. (CVE-2012-5614)

  - Unspecified vulnerability in Oracle MySQL 5.1.67 and earlier, 5.5.29 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect availability via unknown vectors related to Server Locking.
    (CVE-2013-1506)

  - Unspecified vulnerability in Oracle MySQL 5.5.29 and earlier allows remote authenticated users to affect
    availability via unknown vectors related to Data Manipulation Language. (CVE-2013-1512)

  - Unspecified vulnerability in Oracle MySQL 5.1.67 and earlier and 5.5.29 and earlier allows remote
    authenticated users to affect confidentiality, integrity, and availability via unknown vectors related to
    Server Locking. (CVE-2013-1521)

  - Unspecified vulnerability in Oracle MySQL 5.5.29 and earlier and 5.6.10 and earlier allows remote
    authenticated users to affect confidentiality, integrity, and availability via unknown vectors related to
    Server Optimizer. (CVE-2013-1523)

  - Unspecified vulnerability in Oracle MySQL 5.5.29 and earlier allows remote authenticated users to affect
    availability via unknown vectors related to Server Replication. (CVE-2013-1526)

  - Unspecified vulnerability in Oracle MySQL 5.1.67 and earlier and 5.5.29 and earlier allows remote
    authenticated users to affect confidentiality, integrity, and availability via unknown vectors.
    (CVE-2013-1552)

  - Unspecified vulnerability in Oracle MySQL 5.1.67 and earlier, and 5.5.29 and earlier, allows remote
    authenticated users to affect availability via unknown vectors related to Server Partition.
    (CVE-2013-1555)

  - Unspecified vulnerability in Oracle MySQL 5.1.67 and earlier, 5.5.29 and earlier, and 5.6.10 and earlier
    allows remote authenticated users to affect confidentiality, integrity, and availability via unknown
    vectors related to Information Schema. (CVE-2013-2378)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-0-2-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2378");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/24");
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
  { 'min_version' : '10.0', 'fixed_version' : '10.0.2' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
