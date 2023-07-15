#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118094);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2018-8527", "CVE-2018-8532", "CVE-2018-8533");

  script_name(english:"Microsoft SQL Server Management Studio Multiple vulnerabilities (October 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The version of SQL Server Management Studio installed 
on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft SQL Server Management Studio 
installed on the remote Windows host is a version prior 
or equal to 17.9, 18.0 Preview 4. It is, 
therefore, affected by multiple vulnerabilities.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  # https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms?view=sql-server-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00f3184c");
  script_set_attribute(attribute:"solution", value:
"Refer to Microsoft documentation and upgrade to relevant
fixed version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8527");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/12");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server_management_studio");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_ssms_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft SSMS", "Settings/ParanoidReport");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app_info = vcf::get_app_info(app:"Microsoft SSMS");

constraints = [
  { "min_version" : "2017.140.0.0", "max_version": "2017.140.17285.0", "fixed_display" : "Refer to vendor documentation."},
  { "min_version" : "2018.150.0.0", "max_version": "2018.150.18040.0", "fixed_display" : "Refer to vendor documentation."}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, strict:FALSE);
