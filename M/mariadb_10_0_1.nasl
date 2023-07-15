#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167905);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2012-0572",
    "CVE-2012-0574",
    "CVE-2012-0578",
    "CVE-2012-1702",
    "CVE-2012-1705",
    "CVE-2012-5096",
    "CVE-2012-5611",
    "CVE-2012-5612",
    "CVE-2012-5615",
    "CVE-2012-5627",
    "CVE-2013-0367",
    "CVE-2013-0368",
    "CVE-2013-0371",
    "CVE-2013-0383",
    "CVE-2013-0384",
    "CVE-2013-0385",
    "CVE-2013-0386",
    "CVE-2013-0389",
    "CVE-2013-1531"
  );

  script_name(english:"MariaDB 10.0.0 < 10.0.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.0.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-0-1-release-notes advisory.

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier and 5.5.28 and
    earlier allows remote authenticated users to affect availability via unknown vectors related to InnoDB.
    (CVE-2012-0572)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier, and 5.5.28 and
    earlier, allows remote authenticated users to affect availability via unknown vectors. (CVE-2012-0574)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Server Optimizer.
    (CVE-2012-0578)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier and 5.5.28 and
    earlier allows remote attackers to affect availability via unknown vectors. (CVE-2012-1702)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier and 5.5.28 and
    earlier allows remote authenticated users to affect availability via unknown vectors related to Server
    Optimizer. (CVE-2012-1705)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote
    authenticated users with Server Privileges to affect availability via unknown vectors. (CVE-2012-5096)

  - Stack-based buffer overflow in the acl_get function in Oracle MySQL 5.5.19 and other versions through
    5.5.28, and 5.1.53 and other versions through 5.1.66, and MariaDB 5.5.2.x before 5.5.28a, 5.3.x before
    5.3.11, 5.2.x before 5.2.13 and 5.1.x before 5.1.66, allows remote authenticated users to execute
    arbitrary code via a long argument to the GRANT FILE command. (CVE-2012-5611)

  - Heap-based buffer overflow in Oracle MySQL 5.5.19 and other versions through 5.5.28, and MariaDB 5.5.28a
    and possibly other versions, allows remote authenticated users to cause a denial of service (memory
    corruption and crash) and possibly execute arbitrary code, as demonstrated using certain variations of the
    (1) USE, (2) SHOW TABLES, (3) DESCRIBE, (4) SHOW FIELDS FROM, (5) SHOW COLUMNS FROM, (6) SHOW INDEX FROM,
    (7) CREATE TABLE, (8) DROP TABLE, (9) ALTER TABLE, (10) DELETE FROM, (11) UPDATE, and (12) SET PASSWORD
    commands. (CVE-2012-5612)

  - Oracle MySQL 5.5.38 and earlier, 5.6.19 and earlier, and MariaDB 5.5.28a, 5.3.11, 5.2.13, 5.1.66, and
    possibly other versions, generates different error messages with different time delays depending on
    whether a user name exists, which allows remote attackers to enumerate valid usernames. (CVE-2012-5615)

  - Oracle MySQL and MariaDB 5.5.x before 5.5.29, 5.3.x before 5.3.12, and 5.2.x before 5.2.14 does not modify
    the salt during multiple executions of the change_user command within the same connection which makes it
    easier for remote authenticated users to conduct brute force password guessing attacks. (CVE-2012-5627)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Server Partition.
    (CVE-2013-0367)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to InnoDB. (CVE-2013-0368)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote
    authenticated users to affect availability, related to MyISAM. (CVE-2013-0371)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier, and 5.5.28 and
    earlier, allows remote attackers to affect availability via unknown vectors related to Server Locking.
    (CVE-2013-0383)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier, and 5.5.28 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to
    Information Schema. (CVE-2013-0384)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier, and 5.5.28 and
    earlier, allows local users to affect confidentiality and integrity via unknown vectors related to Server
    Replication. (CVE-2013-0385)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.5.28 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Stored Procedure.
    (CVE-2013-0386)

  - Unspecified vulnerability in the Server component in Oracle MySQL 5.1.66 and earlier, and 5.5.28 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to Server
    Optimizer. (CVE-2013-0389)

  - Unspecified vulnerability in Oracle MySQL 5.1.66 and earlier and 5.5.28 and earlier allows remote
    authenticated users to affect confidentiality, integrity, and availability via unknown vectors related to
    Server Privileges. (CVE-2013-1531)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-0-1-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.0.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0385");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-0383");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/06");
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
  { 'min_version' : '10.0', 'fixed_version' : '10.0.1' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
