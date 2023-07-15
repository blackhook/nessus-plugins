#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167879);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id(
    "CVE-2017-3636",
    "CVE-2017-3641",
    "CVE-2017-3653",
    "CVE-2017-10379",
    "CVE-2017-10384"
  );

  script_name(english:"MariaDB 5.5.0 < 5.5.57 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 5.5.57. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-5-5-57-release-notes advisory.

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.57 and earlier, 5.6.37 and earlier and 5.7.19 and earlier. Easily
    exploitable vulnerability allows low privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized access to
    critical data or complete access to all MySQL Server accessible data. (CVE-2017-10379)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: DDL). Supported
    versions that are affected are 5.5.57 and earlier 5.6.37 and earlier 5.7.19 and earlier. Easily
    exploitable vulnerability allows low privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2017-10384)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.56 and earlier and 5.6.36 and earlier. Easily exploitable vulnerability
    allows low privileged attacker with logon to the infrastructure where MySQL Server executes to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data as well as unauthorized read access to a subset of MySQL
    Server accessible data and unauthorized ability to cause a partial denial of service (partial DOS) of
    MySQL Server. (CVE-2017-3636)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: DML). Supported
    versions that are affected are 5.5.56 and earlier, 5.6.36 and earlier and 5.7.18 and earlier. Easily
    exploitable vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2017-3641)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: DDL). Supported
    versions that are affected are 5.5.56 and earlier, 5.6.36 and earlier and 5.7.18 and earlier. Difficult to
    exploit vulnerability allows low privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of MySQL Server accessible data. (CVE-2017-3653)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-5-5-57-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 5.5.57 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3636");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-10379");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/19");
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
  { 'min_version' : '5.5', 'fixed_version' : '5.5.57' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
