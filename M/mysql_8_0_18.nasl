##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(130027);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2019-2911",
    "CVE-2019-2914",
    "CVE-2019-2938",
    "CVE-2019-2946",
    "CVE-2019-2957",
    "CVE-2019-2960",
    "CVE-2019-2963",
    "CVE-2019-2966",
    "CVE-2019-2967",
    "CVE-2019-2968",
    "CVE-2019-2974",
    "CVE-2019-2982",
    "CVE-2019-2991",
    "CVE-2019-2993",
    "CVE-2019-2997",
    "CVE-2019-2998",
    "CVE-2019-3004",
    "CVE-2019-3009",
    "CVE-2019-3011",
    "CVE-2019-3018",
    "CVE-2019-5443",
    "CVE-2020-2580",
    "CVE-2020-2589",
    "CVE-2020-2752",
    "CVE-2021-2001",
    "CVE-2021-2160"
  );
  script_bugtraq_id(108881);
  script_xref(name:"IAVA", value:"2019-A-0383-S");
  script_xref(name:"IAVA", value:"2020-A-0021-S");
  script_xref(name:"IAVA", value:"2020-A-0143-S");
  script_xref(name:"IAVA", value:"2021-A-0038-S");
  script_xref(name:"IAVA", value:"2021-A-0193-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"MySQL 8.0.x < 8.0.18 Multiple Vulnerabilities (Oct 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior
  to 8.0.18. It is, therefore, affected by multiple vulnerabilities, including three of the top vulnerabilities below,
  as noted in the October 2019 Critical Patch Update advisory:

    - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions
  that are affected are 5.7.30 and prior and 8.0.17 and prior. Easily exploitable vulnerability allows high
  privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful attacks of
  this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable crash (complete
  DOS) of MySQL Server. (CVE-2021-2160)

    - Vulnerabilities in the MySQL Server product of Oracle MySQL (components: Server: C API and Optimizer). Easily
  exploitable vulnerabilities which allow low privileged attackers with network access via multiple protocols to
  compromise MySQL Server. Successful exploitation of these vulnerabilities can result in unauthorized ability to cause
  a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2966, CVE-2019-3011)

    - A non-privileged user or program can put code and a config file in a known non-privileged path (under
  C:/usr/local/) that will make curl <= 7.65.1 automatically run the code (as an openssl 'engine') on invocation.
  If that curl is invoked by a privileged user it can do anything it wants. (CVE-2019-5443)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-18.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97fbbe00");
  # https://www.oracle.com/technetwork/security-advisory/cpuoct2019-5072832.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b370bc74");
  # https://www.oracle.com/security-alerts/cpujan2021.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3f5cff95");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuapr2021.html#AppendixMSQL");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuapr2021cvrf.xml");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.18 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2991");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl", "mysql_version_local.nasl", "mysql_win_installed.nbin", "macosx_mysql_installed.nbin");
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.18'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
