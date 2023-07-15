#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126783);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2018-16890",
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2741",
    "CVE-2019-2757",
    "CVE-2019-2758",
    "CVE-2019-2774",
    "CVE-2019-2778",
    "CVE-2019-2791",
    "CVE-2019-2797",
    "CVE-2019-2805",
    "CVE-2019-2819",
    "CVE-2019-2948",
    "CVE-2019-2969",
    "CVE-2019-3822",
    "CVE-2019-3823"
  );
  script_bugtraq_id(
    106947,
    106950,
    109243,
    109247
  );
  script_xref(name:"IAVA", value:"2019-A-0122-S");
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"MySQL 5.7.x < 5.7.27 Multiple Vulnerabilities (Jul 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.7.x prior to
5.7.27. It is, therefore, affected by multiple vulnerabilities,
including three of the top vulnerabilities below, as noted in the
July 2019 Critical Patch Update advisory:

  - A stack-based buffer overflow vulnerability in the
    'Server: Packaging (cURL)' subcomponent could allow an
    unauthenticated attacker to gain complete control of an
    affected instance of MySQL Server. (CVE-2019-3822)

  - A vulnerability in the 'Server: Parser' subcomponent.
    This is an easily exploitable vulnerability that allows
    a low privileged attacker with network access via
    multiple protocols to compromise the server. Successful
    attacks involving this vulnerability can result in the
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS). (CVE-2019-2805)

  - A vulnerability in the 'Server: XML' subcomponent. This
    is an easily exploitable vulnerability that allows a
    low privileged attacker with network access via multiple
    protocols to compromise a server.Successful attacks
    involving this vulnerability can result in the
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS).
    (CVE-2019-2740)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.7/en/news-5-7-27.html");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1adc2fd3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.7.27 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/18");

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

var constraints = [{ 'min_version' : '5.7.0', 'fixed_version' : '5.7.27'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);