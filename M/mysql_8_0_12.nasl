#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111159);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id(
    "CVE-2018-0739",
    "CVE-2018-3054",
    "CVE-2018-3056",
    "CVE-2018-3060",
    "CVE-2018-3062",
    "CVE-2018-3064",
    "CVE-2018-3065",
    "CVE-2018-3067",
    "CVE-2018-3073",
    "CVE-2018-3074",
    "CVE-2018-3075",
    "CVE-2018-3077",
    "CVE-2018-3078",
    "CVE-2018-3079",
    "CVE-2018-3080",
    "CVE-2018-3082",
    "CVE-2018-3084"
  );
  script_bugtraq_id(
    103518,
    104769,
    104772,
    104776,
    104788
  );

  script_name(english:"MySQL 8.0.x < 8.0.12 Multiple Vulnerabilities (Jul 2018 CPU) (Jul 2019 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 8.0.x prior to
8.0.12. It is, therefore, affected by multiple vulnerabilities as
noted in the July 2018 and July 2019 Critical Patch Update advisories.
Please consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/8.0/en/news-8-0-12.html");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 8.0.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3064");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/07/20");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies(
    "mysql_version.nasl", 
    "mysql_login.nasl", 
    "mysql_version_local.nasl", 
    "mysql_win_installed.nbin", 
    "macosx_mysql_installed.nbin"
  );
  script_require_keys("installed_sw/MySQL Server");

  exit(0);
}

include('vcf_extras_mysql.inc');

var app_info = vcf::mysql::combined_get_app_info();

var constraints = [{ 'min_version' : '8.0.0', 'fixed_version' : '8.0.12'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);

