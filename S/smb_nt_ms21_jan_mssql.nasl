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
  script_id(145033);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2021-1636");
  script_xref(name:"IAVA", value:"2021-A-0018-S");
  script_xref(name:"MSKB", value:"4583456");
  script_xref(name:"MSKB", value:"4583457");
  script_xref(name:"MSKB", value:"4583458");
  script_xref(name:"MSKB", value:"4583459");
  script_xref(name:"MSKB", value:"4583460");
  script_xref(name:"MSKB", value:"4583461");
  script_xref(name:"MSKB", value:"4583462");
  script_xref(name:"MSKB", value:"4583463");
  script_xref(name:"MSKB", value:"4583465");
  script_xref(name:"MSFT", value:"MS21-4583456");
  script_xref(name:"MSFT", value:"MS21-4583457");
  script_xref(name:"MSFT", value:"MS21-4583458");
  script_xref(name:"MSFT", value:"MS21-4583459");
  script_xref(name:"MSFT", value:"MS21-4583460");
  script_xref(name:"MSFT", value:"MS21-4583461");
  script_xref(name:"MSFT", value:"MS21-4583462");
  script_xref(name:"MSFT", value:"MS21-4583463");
  script_xref(name:"MSFT", value:"MS21-4583465");
  script_xref(name:"CEA-ID", value:"CEA-2021-0001");

  script_name(english:"Security Updates for Microsoft SQL Server (January 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is missing a security update. It is, therefore, affected by an
elevation of privilege vulnerability. An authenticated, remote attacker can exploit this issue, to gain elevated
privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://support.microsoft.com/en-us/help/4583456/kb4583456-security-update-for-sql-server-2017-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2fa953d");
  # https://support.microsoft.com/en-us/help/4583457/kb4583457-security-update-for-sql-server-2017-cu22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?362bf920");
  # https://support.microsoft.com/en-us/help/4583458/kb4583458-security-update-for-sql-server-2019-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?833fc41a");
  # https://support.microsoft.com/en-us/help/4583459/kb4583459-security-update-for-sql-server-2019-cu8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?085ac1e7");
  # https://support.microsoft.com/en-us/help/4583465/kb4583465-description-of-the-security-update-for-sql-server-2012-sp4-g
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85a48b10");
  # https://support.microsoft.com/en-us/help/4583463/kb4583463-security-update-for-sql-server-2014-sp3-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f323c3fb");
  # https://support.microsoft.com/en-us/help/4583462/kb4583462-security-update-for-sql-server-2014-sp3-cu4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cdd8de3f");
  # https://support.microsoft.com/en-us/help/4583461/kb4583461-security-update-for-sql-server-2016-sp2-cu15
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?add91580");
  # https://support.microsoft.com/en-us/help/4583460/kb4583460-security-update-for-sql-server-2016-sp2-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0dbdcec2");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4583456
  -KB4583457
  -KB4583458
  -KB4583459
  -KB4583460
  -KB4583461
  -KB4583462
  -KB4583463
  -KB4583465");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product_version' : '2012',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2011.110.7001.0',
    'fixed_version'   : '2011.110.7507.2',
    'kb'              : '4583465'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6205.1',
    'fixed_version'   : '2014.120.6433.1',
    'kb'              : '4583462'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6024.0',
    'fixed_version'   : '2014.120.6164.21',
    'kb'              : '4583463'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.5026.0',
    'fixed_version'   : '2015.131.5103.6',
    'kb'              : '4583460'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.5149.0',
    'fixed_version'   : '2015.131.5865.1',
    'kb'              : '4583461'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2037.2',
    'kb'              : '4583456'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3370.1',
    'kb'              : '4583457'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2080.9',
    'kb'              : '4583458'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4083.2',
    'kb'              : '4583459'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS21-01',
  severity          : SECURITY_WARNING
);