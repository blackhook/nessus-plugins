##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148937);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-28196",
    "CVE-2021-2146",
    "CVE-2021-2162",
    "CVE-2021-2164",
    "CVE-2021-2166",
    "CVE-2021-2169",
    "CVE-2021-2170",
    "CVE-2021-2171",
    "CVE-2021-2172",
    "CVE-2021-2174",
    "CVE-2021-2179",
    "CVE-2021-2180",
    "CVE-2021-2193",
    "CVE-2021-2194",
    "CVE-2021-2196",
    "CVE-2021-2201",
    "CVE-2021-2203",
    "CVE-2021-2208",
    "CVE-2021-2212",
    "CVE-2021-2215",
    "CVE-2021-2217",
    "CVE-2021-2226",
    "CVE-2021-2230",
    "CVE-2021-2232",
    "CVE-2021-2278",
    "CVE-2021-2293",
    "CVE-2021-2298",
    "CVE-2021-2299",
    "CVE-2021-2300",
    "CVE-2021-2301",
    "CVE-2021-2304",
    "CVE-2021-2305",
    "CVE-2021-2307",
    "CVE-2021-2308",
    "CVE-2021-2444",
    "CVE-2021-3449",
    "CVE-2021-23841"
  );
  script_xref(name:"IAVA", value:"2021-A-0193");
  script_xref(name:"IAVA", value:"2021-A-0333");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"MySQL 8.0.x < 8.0.24 Multiple Vulnerabilities (Apr 2021 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to 8.0.24. It is, therefore, affected by multiple
vulnerabilities, including the following, as noted in the April 2021 Critical Patch Update advisory:

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging (OpenSSL)).
  Supported versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability
  allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server. Successful
  attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash
  (complete DOS) of MySQL Server. (CVE-2021-3449)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Security: Encryption
  (OpenSSL)). Supported versions that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable
  vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Server.
  Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
  repeatable crash (complete DOS) of MySQL Server. (CVE-2021-23841)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Packaging). Supported versions
  that are affected are 5.7.33 and prior and 8.0.23 and prior. Easily exploitable vulnerability allows
  unauthenticated attacker with logon to the infrastructure where MySQL Server executes to compromise MySQL Server.
  Successful attacks require human interaction from a person other than the attacker. Successful attacks of this
  vulnerability can result in unauthorized access to critical data or complete access to all MySQL Server
  accessible data as well as unauthorized update, insert or delete access to some of MySQL Server accessible data. (CVE-2020-28196)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.24 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-2304");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-2307");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.24'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
