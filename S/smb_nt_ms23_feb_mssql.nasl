#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171604);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id(
    "CVE-2023-21528",
    "CVE-2023-21568",
    "CVE-2023-21704",
    "CVE-2023-21705",
    "CVE-2023-21713",
    "CVE-2023-21718"
  );
  script_xref(name:"MSKB", value:"5020863");
  script_xref(name:"MSKB", value:"5021112");
  script_xref(name:"MSKB", value:"5021126");
  script_xref(name:"MSKB", value:"5021129");
  script_xref(name:"MSKB", value:"5021522");
  script_xref(name:"MSKB", value:"5021127");
  script_xref(name:"MSKB", value:"5021045");
  script_xref(name:"MSKB", value:"5021037");
  script_xref(name:"MSKB", value:"5021128");
  script_xref(name:"MSKB", value:"5021123");
  script_xref(name:"MSKB", value:"5021124");
  script_xref(name:"MSKB", value:"5021125");
  script_xref(name:"MSFT", value:"MS23-5020863");
  script_xref(name:"MSFT", value:"MS23-5021112");
  script_xref(name:"MSFT", value:"MS23-5021126");
  script_xref(name:"MSFT", value:"MS23-5021129");
  script_xref(name:"MSFT", value:"MS23-5021522");
  script_xref(name:"MSFT", value:"MS23-5021127");
  script_xref(name:"MSFT", value:"MS23-5021045");
  script_xref(name:"MSFT", value:"MS23-5021037");
  script_xref(name:"MSFT", value:"MS23-5021128");
  script_xref(name:"MSFT", value:"MS23-5021124");
  script_xref(name:"MSFT", value:"MS23-5021125");
  script_xref(name:"IAVA", value:"2023-A-0086");

  script_name(english:"Security Updates for Microsoft SQL Server (February 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing security updates. It is, therefore, affected by
multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2023-21528,
    CVE-2023-21568, CVE-2023-21704, CVE-2023-21705,
    CVE-2023-21713, CVE-2023-21718)");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5020863");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021112");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021126");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021129");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021522");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021127");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021045");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021037");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021128");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021123");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021124");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5021125");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5021126
  -KB5021129
  -KB5021522
  -KB5021127
  -KB5021045
  -KB5021037
  -KB5021128
  -KB5021124
  -KB5021125
  -KB5020863
  -KB5021112
  -KB5021123");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-21713");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product_version' : '2008',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2007.100.1600.1',
    'fixed_version'   : '2007.100.6814.4',
    'kb'              : '5020863'
  },
  {
    'product_version' : '2008',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2009.100.6000.34',
    'fixed_version'   : '2009.100.6785.2',
    'kb'              : '5021112'
  },
  {
    'product_version' : '2012',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2011.110.7001.0',
    'fixed_version'   : '2011.110.7512.11',
    'kb'              : '5021123'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6024.0',
    'fixed_version'   : '2014.120.6174.8',
    'kb'              : '5021037'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.6205.1',
    'fixed_version'   : '2014.120.6444.4',
    'kb'              : '5021045' 
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.6300.2',
    'fixed_version'   : '2015.131.6430.49',
    'kb'              : '5021129'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.131.7000.253',
    'fixed_version'   : '2015.131.7024.30',
    'kb'              : '5021128'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.1000.169',
    'fixed_version'   : '2017.140.2047.8',
    'kb'              : '5021127'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.16',
    'fixed_version'   : '2017.140.3460.9',
    'kb'              : '5021126'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.2000.5',
    'fixed_version'   : '2019.150.2101.7',
    'kb'              : '5021125'
  },
  {
    'product_version' : '2019',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2019.150.4003.23',
    'fixed_version'   : '2019.150.4280.7',
    'kb'              : '5021124'
  },
  {
    'product_version' : '2022',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2022.160.1000.6',
    'fixed_version'   : '2022.160.1050.5',
    'kb'              : '5021522'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  bulletin          : 'MS23-02',
  severity          : SECURITY_HOLE
);