#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(167902);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/11/21");

  script_cve_id(
    "CVE-2015-4792",
    "CVE-2015-4802",
    "CVE-2015-4807",
    "CVE-2015-4815",
    "CVE-2015-4816",
    "CVE-2015-4819",
    "CVE-2015-4826",
    "CVE-2015-4830",
    "CVE-2015-4836",
    "CVE-2015-4858",
    "CVE-2015-4861",
    "CVE-2015-4864",
    "CVE-2015-4866",
    "CVE-2015-4870",
    "CVE-2015-4879",
    "CVE-2015-4895",
    "CVE-2015-4913"
  );

  script_name(english:"MariaDB 10.1.0 < 10.1.8 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MariaDB installed on the remote host is prior to 10.1.8. It is, therefore, affected by multiple
vulnerabilities as referenced in the mariadb-10-1-8-release-notes advisory.

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Server : Partition, a different
    vulnerability than CVE-2015-4802. (CVE-2015-4792)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier allows remote
    authenticated users to affect availability via unknown vectors related to Server : Partition, a different
    vulnerability than CVE-2015-4792. (CVE-2015-4802)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier, when running
    on Windows, allows remote authenticated users to affect availability via unknown vectors related to Server
    : Query Cache. (CVE-2015-4807)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier allows remote
    authenticated users to affect availability via vectors related to Server : DDL. (CVE-2015-4815)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.44 and earlier allows remote authenticated users to
    affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4816)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.44 and earlier, and 5.6.25 and earlier, allows local
    users to affect confidentiality, integrity, and availability via unknown vectors related to Client
    programs. (CVE-2015-4819)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier allows remote
    authenticated users to affect confidentiality via unknown vectors related to Server : Types.
    (CVE-2015-4826)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier allows remote
    authenticated users to affect integrity via unknown vectors related to Server : Security : Privileges.
    (CVE-2015-4830)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote
    authenticated users to affect availability via unknown vectors related to Server : SP. (CVE-2015-4836)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote
    authenticated users to affect availability via vectors related to DML, a different vulnerability than
    CVE-2015-4913. (CVE-2015-4858)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote
    authenticated users to affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4861)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.43 and earlier and 5.6.24 and earlier allows remote
    authenticated users to affect integrity via unknown vectors related to Server : Security : Privileges.
    (CVE-2015-4864)

  - Unspecified vulnerability in Oracle MySQL Server 5.6.23 and earlier allows remote authenticated users to
    affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4866)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier, and 5.6.26 and earlier, allows remote
    authenticated users to affect availability via unknown vectors related to Server : Parser. (CVE-2015-4870)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.44 and earlier, and 5.6.25 and earlier, allows remote
    authenticated users to affect confidentiality, integrity, and availability via vectors related to DML.
    (CVE-2015-4879)

  - Unspecified vulnerability in Oracle MySQL Server 5.6.25 and earlier allows remote authenticated users to
    affect availability via unknown vectors related to Server : InnoDB. (CVE-2015-4895)

  - Unspecified vulnerability in Oracle MySQL Server 5.5.45 and earlier and 5.6.26 and earlier allows remote
    authenticated users to affect availability via vectors related to Server : DML, a different vulnerability
    than CVE-2015-4858. (CVE-2015-4913)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mariadb.com/kb/en/mariadb-10-1-8-release-notes");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MariaDB version 10.1.8 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4819");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-4913");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/17");
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
  { 'min_version' : '10.1', 'fixed_version' : '10.1.8' }
];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
