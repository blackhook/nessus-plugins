#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126784);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/25");

  script_cve_id(
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2741",
    "CVE-2019-2752",
    "CVE-2019-2757",
    "CVE-2019-2758",
    "CVE-2019-2774",
    "CVE-2019-2778",
    "CVE-2019-2780",
    "CVE-2019-2784",
    "CVE-2019-2785",
    "CVE-2019-2789",
    "CVE-2019-2791",
    "CVE-2019-2795",
    "CVE-2019-2796",
    "CVE-2019-2797",
    "CVE-2019-2800",
    "CVE-2019-2801",
    "CVE-2019-2802",
    "CVE-2019-2803",
    "CVE-2019-2805",
    "CVE-2019-2808",
    "CVE-2019-2810",
    "CVE-2019-2811",
    "CVE-2019-2812",
    "CVE-2019-2814",
    "CVE-2019-2815",
    "CVE-2019-2819",
    "CVE-2019-2822",
    "CVE-2019-2826",
    "CVE-2019-2830",
    "CVE-2019-2834",
    "CVE-2019-2879",
    "CVE-2019-2948",
    "CVE-2019-2950",
    "CVE-2019-2969",
    "CVE-2019-3003",
    "CVE-2022-21589"
  );
  script_bugtraq_id(109234, 109243, 109247);
  script_xref(name:"IAVA", value:"2019-A-0383-S");

  script_name(english:"MySQL 8.0.x < 8.0.17 Multiple Vulnerabilities (July 2019 CPU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to
8.0.17. It is, therefore, affected by multiple vulnerabilities,
including three of the top vulnerabilities below, as noted in the
July 2019 and October 2022 Critical Patch Update advisories:

  - An unspecified vulnerability in the
    'Shell: Admin / InnoDB Cluster' subcomponent could allow
    an unauthenticated attacker to takeover an affected MySQL
    Server. A successful attack requires user interaction.
    (CVE-2019-2822)

  - As unspecified vulnerability in the 'Server: Replication'
    subcomponent could allow an unauthenticated attacker to
    cause the server to hang or to, via a frequently
    repeatable crash, cause a complete denial of service.
    Additionally, a successful attacker could perform
    unauthorized modifications to some MySQL Server
    accessible data. (CVE-2019-2800)

  - As unspecified vulnerability in the 'Server: Charsets'
    subcomponent could allow an unauthenticated attacker to
    cause the server to hang or to, via a frequently
    repeatable crash, cause a complete denial of service.
    (CVE-2019-2795)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-17.html");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2019-5072835.html#AppendixMSQL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1adc2fd3");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/a/tech/docs/cpuoct2022cvrf.xml");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/security-alerts/cpuoct2022.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.17 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-2819");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-2822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/16");
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

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.17'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
