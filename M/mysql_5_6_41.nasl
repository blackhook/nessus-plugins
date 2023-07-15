#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(111155);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_bugtraq_id(
    103518,
    103954,
    104766,
    104776,
    104779
  );

  

  script_name(english:"MySQL 5.6.x < 5.6.41 Multiple Vulnerabilities (July 2018 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.41. It is, therefore, affected by multiple vulnerabilities as
noted in the July 2018 Critical Patch Update advisory. Please consult
the CVRF details for the applicable CVEs for additional information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");

  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-41.html");
  # http://www.oracle.com/technetwork/security-advisory/cpujul2018-4258247.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50f36723");

  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.41 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-3064");


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

var constraints = [{ 'min_version' : '5.6.0', 'fixed_version' : '5.6.41'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);