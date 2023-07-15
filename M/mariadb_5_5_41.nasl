#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167857);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2014-6568",
    "CVE-2015-0374",
    "CVE-2015-0381",
    "CVE-2015-0382",
    "CVE-2015-0411",
    "CVE-2015-0432"
  );

  script_name(english:"MariaDB 5.5.0 < 5.5.41 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.41. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-5-5-41-release-notes advisory.

  - Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier, and 5.6.21 and earlier, allows remote
    authenticated users to affect availability via vectors related to Server : InnoDB : DML. (CVE-2014-6568)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier and 5.6.21 and earlier allows remote
    authenticated users to affect confidentiality via unknown vectors related to Server : Security :
    Privileges : Foreign Key. (CVE-2015-0374)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier and 5.6.21 and earlier allows remote
    attackers to affect availability via unknown vectors related to Server : Replication, a different
    vulnerability than CVE-2015-0382. (CVE-2015-0381)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier and 5.6.21 and earlier allows remote
    attackers to affect availability via unknown vectors related to Server : Replication, a different
    vulnerability than CVE-2015-0381. (CVE-2015-0382)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier, and 5.6.21 and earlier, allows remote
    attackers to affect confidentiality, integrity, and availability via unknown vectors related to Server :
    Security : Encryption. (CVE-2015-0411)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.40 and earlier allows remote authenticated users to
    affect availability via vectors related to Server : InnoDB : DDL : Foreign Key. (CVE-2015-0432)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5-5-41-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.41 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0411");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-0382");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/21");
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
  { 'min_version' : '5.5', 'fixed_version' : '5.5.41' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
