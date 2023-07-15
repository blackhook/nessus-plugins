#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(162393);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2022-29143");
  script_xref(name:"IAVA", value:"2022-A-0244-S");
  script_xref(name:"MSKB", value:"5015371");
  script_xref(name:"MSKB", value:"5014553");
  script_xref(name:"MSKB", value:"5014351");
  script_xref(name:"MSKB", value:"5014353");
  script_xref(name:"MSKB", value:"5014354");
  script_xref(name:"MSKB", value:"5014356");
  script_xref(name:"MSKB", value:"5014365");
  script_xref(name:"MSKB", value:"5014355");
  script_xref(name:"MSKB", value:"5014165");
  script_xref(name:"MSKB", value:"5014164");
  script_xref(name:"MSFT", value:"MS22-5015371");
  script_xref(name:"MSFT", value:"MS22-5014553");
  script_xref(name:"MSFT", value:"MS22-5014351");
  script_xref(name:"MSFT", value:"MS22-5014353");
  script_xref(name:"MSFT", value:"MS22-5014354");
  script_xref(name:"MSFT", value:"MS22-5014356");
  script_xref(name:"MSFT", value:"MS22-5014365");
  script_xref(name:"MSFT", value:"MS22-5014355");
  script_xref(name:"MSFT", value:"MS22-5014165");
  script_xref(name:"MSFT", value:"MS22-5014164");

  script_name(english:"Security Updates for Microsoft SQL Server (June 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is missing a security update. It is, therefore, affected by the
following vulnerability:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2022-29143)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5015371");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014553");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014351");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014353");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014354");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014356");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014365");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014355");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014165");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5014164");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5015371
  -KB5014553
  -KB5014351
  -KB5014353
  -KB5014354
  -KB5014356
  -KB5014365
  -KB5014355
  -KB5014165
  -KB5014164");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29143");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "installed_sw/Microsoft SQL Server");
  script_require_ports(139, 445, 1433, "Services/mssql", "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::mssql::get_app_info();

var constraints =
[
  {
    'product_version' : '2014',
    'target_hw'     : 'x64, x86',
    'file'          : 'sqlservr.exe',
    'min_version'   : '2014.120.6205.1',
    'fixed_version' : '2014.120.6439.10',
    'kb'            : '5014164'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6024.0',
    'fixed_version'   : '2014.120.6169.19',
    'kb'              : '5014165'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.5026.0',
    'fixed_version'   : '2015.131.5108.50',
    'kb'              : '5014365'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.5149.0',
    'fixed_version'   : '2015.131.5893.48',
    'kb'              : '5014351'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.6300.2',
    'fixed_version'   : '2015.131.6419.1',
    'kb'              : '5014355'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.7000.253',
    'fixed_version'   : '2015.131.7016.1',
    'kb'              : '5015371'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2042.3',
    'kb'              : '5014354'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3445.2',
    'kb'              : '5014553'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2095.3',
    'kb'              : '5014356'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4236.7',
    'kb'              : '5014353'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  severity          : SECURITY_WARNING
);