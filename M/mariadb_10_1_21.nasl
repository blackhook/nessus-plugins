#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167880);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2016-6664",
    "CVE-2017-3238",
    "CVE-2017-3243",
    "CVE-2017-3244",
    "CVE-2017-3257",
    "CVE-2017-3258",
    "CVE-2017-3265",
    "CVE-2017-3291",
    "CVE-2017-3312",
    "CVE-2017-3317",
    "CVE-2017-3318"
  );

  script_name(english:"MariaDB 10.1.0 < 10.1.21 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.1.21. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-1-21-release-notes advisory.

  - mysqld_safe in Oracle MySQL through 5.5.51, 5.6.x through 5.6.32, and 5.7.x through 5.7.14; MariaDB;
    Percona Server before 5.5.51-38.2, 5.6.x before 5.6.32-78-1, and 5.7.x before 5.7.14-8; and Percona XtraDB
    Cluster before 5.5.41-37.0, 5.6.x before 5.6.32-25.17, and 5.7.x before 5.7.14-26.17, when using file-
    based logging, allows local users with access to the mysql account to gain root privileges via a symlink
    attack on error logs and possibly other files. (CVE-2016-6664)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Optimizer). Supported
    versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Easily
    exploitable vulnerability allows low privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 6.5
    (Availability impacts). (CVE-2017-3238)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Charsets). Supported
    versions that are affected are 5.5.53 and earlier. Difficult to exploit vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 4.4 (Availability impacts). (CVE-2017-3243)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: DML). Supported
    versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Easily
    exploitable vulnerability allows low privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 6.5
    (Availability impacts). (CVE-2017-3244)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: InnoDB). Supported
    versions that are affected are 5.6.34 and earlier5.7.16 and earlier. Easily exploitable vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 6.5 (Availability impacts).
    (CVE-2017-3257)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: DDL). Supported
    versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Easily
    exploitable vulnerability allows low privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 6.5
    (Availability impacts). (CVE-2017-3258)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Packaging). Supported
    versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Difficult to
    exploit vulnerability allows high privileged attacker with logon to the infrastructure where MySQL Server
    executes to compromise MySQL Server. Successful attacks require human interaction from a person other than
    the attacker. Successful attacks of this vulnerability can result in unauthorized access to critical data
    or complete access to all MySQL Server accessible data and unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 5.6 (Confidentiality and
    Availability impacts). (CVE-2017-3265)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Packaging). Supported
    versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Difficult to
    exploit vulnerability allows high privileged attacker with logon to the infrastructure where MySQL Server
    executes to compromise MySQL Server. Successful attacks require human interaction from a person other than
    the attacker. Successful attacks of this vulnerability can result in takeover of MySQL Server. CVSS v3.0
    Base Score 6.3 (Confidentiality, Integrity and Availability impacts). (CVE-2017-3291)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Packaging). Supported
    versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Difficult to
    exploit vulnerability allows low privileged attacker with logon to the infrastructure where MySQL Server
    executes to compromise MySQL Server. Successful attacks require human interaction from a person other than
    the attacker. Successful attacks of this vulnerability can result in takeover of MySQL Server. CVSS v3.0
    Base Score 6.7 (Confidentiality, Integrity and Availability impacts). (CVE-2017-3312)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Logging). Supported versions
    that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier. Difficult to exploit
    vulnerability allows high privileged attacker with logon to the infrastructure where MySQL Server executes
    to compromise MySQL Server. Successful attacks require human interaction from a person other than the
    attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of MySQL Server. CVSS v3.0 Base Score 4.0 (Availability
    impacts). (CVE-2017-3317)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Error Handling).
    Supported versions that are affected are 5.5.53 and earlier, 5.6.34 and earlier and 5.7.16 and earlier.
    Difficult to exploit vulnerability allows high privileged attacker with logon to the infrastructure where
    MySQL Server executes to compromise MySQL Server. Successful attacks require human interaction from a
    person other than the attacker. Successful attacks of this vulnerability can result in unauthorized access
    to critical data or complete access to all MySQL Server accessible data. CVSS v3.0 Base Score 4.0
    (Confidentiality impacts). (CVE-2017-3318)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-1-21-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.21 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6664");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/18");
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
  { 'min_version' : '10.1', 'fixed_version' : '10.1.21' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
