#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167906);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/01");

  script_cve_id(
    "CVE-2013-1861",
    "CVE-2013-3783",
    "CVE-2013-3793",
    "CVE-2013-3802",
    "CVE-2013-3804",
    "CVE-2013-3809",
    "CVE-2013-3812",
    "CVE-2016-0502"
  );

  script_name(english:"MariaDB 10.0.0 < 10.0.4 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.0.4. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-0-4-release-notes advisory.

  - MariaDB 5.5.x before 5.5.30, 5.3.x before 5.3.13, 5.2.x before 5.2.15, and 5.1.x before 5.1.68, and Oracle
    MySQL 5.1.69 and earlier, 5.5.31 and earlier, and 5.6.11 and earlier allows remote attackers to cause a
    denial of service (crash) via a crafted geometry feature that specifies a large number of points, which is
    not properly handled when processing the binary representation of this feature, related to a numeric
    calculation error. (CVE-2013-1861)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.31 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Server Parser. (CVE-2013-3783)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.31 and earlier and 5.6.11 and
    earlier allows remote authenticated users to affect availability via unknown vectors related to Data
    Manipulation Language. (CVE-2013-3793)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.69 and earlier, 5.5.31 and
    earlier, and 5.6.11 and earlier allows remote authenticated users to affect availability via unknown
    vectors related to Full Text Search. (CVE-2013-3802)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.69 and earlier, 5.5.31 and
    earlier, and 5.6.11 and earlier allows remote authenticated users to affect availability via unknown
    vectors related to Server Optimizer. (CVE-2013-3804)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.31 and earlier and 5.6.11 and
    earlier allows remote authenticated users to affect integrity via unknown vectors related to Audit Log.
    (CVE-2013-3809)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.5.31 and earlier and 5.6.11 and
    earlier allows remote authenticated users to affect availability via unknown vectors related to Server
    Replication. (CVE-2013-3812)

  - Unspecified vulnerability in Oracle MySQL 5.5.31 and earlier and 5.6.11 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Optimizer. (CVE-2016-0502)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-0-4-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-0502");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mariadb:mariadb");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  { 'min_version' : '10.0', 'fixed_version' : '10.0.4' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
