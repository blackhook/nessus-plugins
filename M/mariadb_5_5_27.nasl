#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167851);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/06");

  script_cve_id(
    "CVE-2012-3150",
    "CVE-2012-3158",
    "CVE-2012-3163",
    "CVE-2012-3166",
    "CVE-2012-3167",
    "CVE-2012-3173",
    "CVE-2012-3177",
    "CVE-2012-3197",
    "CVE-2012-4414",
    "CVE-2013-1548"
  );

  script_name(english:"MariaDB 5.5.0 < 5.5.27 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.27. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-5-5-27-release-notes advisory.

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.64 and earlier, and 5.5.26 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to Server
    Optimizer. (CVE-2012-3150)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.64 and earlier, and 5.5.26 and
    earlier, allows remote attackers to affect confidentiality, integrity, and availability via unknown
    vectors related to Protocol. (CVE-2012-3158)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.64 and earlier, and 5.5.26 and
    earlier, allows remote authenticated users to affect confidentiality, integrity, and availability via
    unknown vectors related to Information Schema. (CVE-2012-3163)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.63 and earlier, and 5.5.25 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to InnoDB.
    (CVE-2012-3166)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.63 and earlier, and 5.5.25 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to Server
    Full Text Search. (CVE-2012-3167)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.63 and earlier, and 5.5.25 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to InnoDB
    Plugin. (CVE-2012-3173)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.65 and earlier, and 5.5.27 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to Server.
    (CVE-2012-3177)

  - Unspecified vulnerability in the MySQL Server component in Oracle MySQL 5.1.64 and earlier, and 5.5.26 and
    earlier, allows remote authenticated users to affect availability via unknown vectors related to Server
    Replication. (CVE-2012-3197)

  - Multiple SQL injection vulnerabilities in the replication code in Oracle MySQL possibly before 5.5.29, and
    MariaDB 5.1.x through 5.1.62, 5.2.x through 5.2.12, 5.3.x through 5.3.7, and 5.5.x through 5.5.25, allow
    remote authenticated users to execute arbitrary SQL commands via vectors related to the binary log. NOTE:
    as of 20130116, Oracle has not commented on claims from a downstream vendor that the fix in MySQL 5.5.29
    is incomplete. (CVE-2012-4414)

  - Unspecified vulnerability in Oracle MySQL 5.1.63 and earlier allows remote authenticated users to affect
    availability via unknown vectors related to Server Types. (CVE-2013-1548)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5-5-27-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.27 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-3163");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-4414");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/07");
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
  { 'min_version' : '5.5', 'fixed_version' : '5.5.27' }
];
vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'sqli':TRUE}
);
