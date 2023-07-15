#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(106097);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/21");

  script_cve_id(
    "CVE-2018-2562",
    "CVE-2018-2622",
    "CVE-2018-2640",
    "CVE-2018-2665",
    "CVE-2018-2668"
  );
  script_bugtraq_id(
    102495,
    102706,
    102678,
    102681,
    102682,
    102713
  );

  script_name(english:"MySQL 5.5.x < 5.5.59 Multiple Vulnerabilities (January 2018 CPU)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.5.x prior to
5.5.59. It is, therefore, affected by multiple vulnerabilities as
noted in the January 2018 Critical Patch Update advisory. Please
consult the CVRF details for the applicable CVEs for additional
information.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.5/en/news-5-5-59.html");
  # http://www.oracle.com/technetwork/security-advisory/cpujan2018-3236628.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae82f1b1");
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/4110638.xml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17a0bb67");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.5.59 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2562");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/17");

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

var constraints = [{ 'min_version' : '5.5.0', 'fixed_version' : '5.5.59'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
