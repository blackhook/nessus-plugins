#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111786);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2018-8273");
  script_xref(name:"MSFT", value:"MS18-4458842");
  script_xref(name:"MSFT", value:"MS18-4293808");
  script_xref(name:"MSFT", value:"MS18-4293802");
  script_xref(name:"MSFT", value:"MS18-4458621");
  script_xref(name:"MSFT", value:"MS18-4293803");
  script_xref(name:"MSFT", value:"MS18-4293805");
  script_xref(name:"MSKB", value:"4458842");
  script_xref(name:"MSKB", value:"4293808");
  script_xref(name:"MSKB", value:"4293802");
  script_xref(name:"MSKB", value:"4458621");
  script_xref(name:"MSKB", value:"4293803");
  script_xref(name:"MSKB", value:"4293805");

  script_name(english:"Security Updates for Microsoft SQL Server 2016 and 2017 x64 (August 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by buffer overflow vulnerability that could allow
remote code execution on an affected system.
An attacker who successfully exploited the vulnerability could execute code
in the context of the SQL Server Database Engine service account.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-8273
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?02637930");
  # https://support.microsoft.com/en-us/help/4458842/description-of-the-security-update-for-the-remote-code-execution-vulne
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5296772");
  # https://support.microsoft.com/en-us/help/4293808/security-update-for-remote-code-execution-vulnerability-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ded4707c");
  # https://support.microsoft.com/en-us/help/4293802/description-of-the-security-update-for-the-remote-code-execution-vulne
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc2f6328");
  # https://support.microsoft.com/en-us/help/4458621/description-of-the-security-update-for-the-remote-code-execution
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4ab5e14c");
  # https://support.microsoft.com/en-us/help/4293803/description-of-the-security-update-for-the-remote-code-execution-vulne
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c6a7711");
  # https://support.microsoft.com/en-us/help/4293805/security-update-for-remote-code-execution-vulnerability-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?82d9f22e");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for x64 versions of SQL Server 2016 and 2017.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8273");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::mssql::get_app_info();

var constraints =
[
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.4001.0',
    'fixed_version'   : '2015.130.4224.16',
    'kb'              : '4458842'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.4411.0',
    'fixed_version'   : '2015.130.4522.0',
    'kb'              : '4293808'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.131.5026.0',
    'fixed_version'   : '2015.131.5081.1',
    'kb'              : '4293802'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.131.5149.0',
    'fixed_version'   : '2015.131.5201.2',
    'kb'              : '4458621'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2002.14',
    'kb'              : '4293803'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3035.2',
    'kb'              : '4293805'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS18-08',
  severity          : SECURITY_WARNING
);