#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167856);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/18");

  script_cve_id("CVE-2017-15365", "CVE-2018-3133");

  script_name(english:"MariaDB 10.1.0 < 10.1.30 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.1.30. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-1-30-release-notes advisory.

  - sql/event_data_objects.cc in MariaDB before 10.1.30 and 10.2.x before 10.2.10 and Percona XtraDB Cluster
    before 5.6.37-26.21-3 and 5.7.x before 5.7.19-29.22-3 allows remote authenticated users with SQL access to
    bypass intended access restrictions and replicate data definition language (DDL) statements to cluster
    nodes by leveraging incorrect ordering of DDL replication and ACL checking. (CVE-2017-15365)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Parser). Supported
    versions that are affected are 5.5.61 and prior, 5.6.41 and prior, 5.7.23 and prior and 8.0.12 and prior.
    Easily exploitable vulnerability allows low privileged attacker with network access via multiple protocols
    to compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2018-3133)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-1-30-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.30 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/22");
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
  { 'min_version' : '10.1', 'fixed_version' : '10.1.30' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
