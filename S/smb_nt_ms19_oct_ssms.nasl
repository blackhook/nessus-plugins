#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129715);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2019-1313", "CVE-2019-1376");
  script_xref(name:"IAVA", value:"2019-A-0367-S");

  script_name(english:"Microsoft SQL Server Management Studio 18.x < 18.3.1 Multiple Vulnerabilities (October 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The version of SQL Server Management Studio installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft SQL Server Management Studio installed on the remote Windows host is 18.x prior to 18.3.1. It
is, therefore, affected by multiple information disclosure vulnerabilities:

  - An information disclosure vulnerability exists in Microsoft SQL Server Management Studio (SSMS) when it
    improperly enforces permissions. An attacker could exploit the vulnerability if the attacker's credentials
    allow access to an affected SQL server database. An attacker who successfully exploited the vulnerability
    could gain additional database and file information. (CVE-2019-1313) (CVE-2019-1376)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00f3184c");
  script_set_attribute(attribute:"solution", value:
"Update to Microsoft SQL Server Management Studio 18.3.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1376");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/08");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server_management_studio");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_ssms_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft SSMS", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Microsoft SSMS");

# 18.0 is 2019.150.18118.0
# 18.3.1 is 2019.150.18183.0
constraints = [
  { "min_version":"2019.150.18118.0", "fixed_version":"2019.150.18183.0", "fixed_display":"2019.150.18183.0 (18.3.1)"}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
