#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167884);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-3058",
    "CVE-2018-3063",
    "CVE-2018-3066",
    "CVE-2018-3081",
    "CVE-2020-14550",
    "CVE-2021-2011"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"MariaDB 5.5.0 < 5.5.61 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.61. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-5-5-61-release-notes advisory.

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: MyISAM). Supported versions
    that are affected are 5.5.60 and prior, 5.6.40 and prior and 5.7.22 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data. (CVE-2018-3058)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.5.60 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2018-3063)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Options). Supported
    versions that are affected are 5.5.60 and prior, 5.6.40 and prior and 5.7.22 and prior. Difficult to
    exploit vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of MySQL Server accessible data as well as unauthorized read access to a
    subset of MySQL Server accessible data. (CVE-2018-3066)

  - Vulnerability in the MySQL Client component of Oracle MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.60 and prior, 5.6.40 and prior, 5.7.22 and prior and 8.0.11 and prior.
    Difficult to exploit vulnerability allows high privileged attacker with network access via multiple
    protocols to compromise MySQL Client. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Client as well as
    unauthorized update, insert or delete access to some of MySQL Client accessible data. (CVE-2018-3081)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.48 and prior, 5.7.30 and prior and 8.0.20 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. (CVE-2020-14550)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.7.32 and prior and 8.0.22 and prior. Difficult to exploit vulnerability allows
    unauthenticated attacker with network access via multiple protocols to compromise MySQL Client. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Client. (CVE-2021-2011)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5-5-61-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.61 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3081");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/31");
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
  { 'min_version' : '5.5', 'fixed_version' : '5.5.61' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
