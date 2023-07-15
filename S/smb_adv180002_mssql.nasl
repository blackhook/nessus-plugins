#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105613);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2017-5715", "CVE-2017-5753", "CVE-2017-5754");
  script_bugtraq_id(102371, 102376, 102378);
  script_xref(name:"MSFT", value:"4057113");
  script_xref(name:"MSFT", value:"4057114");
  script_xref(name:"MSFT", value:"4057115");
  script_xref(name:"MSFT", value:"4057116");
  script_xref(name:"MSFT", value:"4057117");
  script_xref(name:"MSFT", value:"4057118");
  script_xref(name:"MSFT", value:"4057119");
  script_xref(name:"MSFT", value:"4057120");
  script_xref(name:"MSFT", value:"4057121");
  script_xref(name:"MSFT", value:"4057122");
  script_xref(name:"MSFT", value:"4052987");
  script_xref(name:"MSFT", value:"4058559");
  script_xref(name:"MSFT", value:"4058560");
  script_xref(name:"IAVA", value:"2018-A-0019");
  script_xref(name:"IAVA", value:"2018-A-0020");
  script_xref(name:"MSKB", value:"4057113");
  script_xref(name:"MSKB", value:"4057114");
  script_xref(name:"MSKB", value:"4057115");
  script_xref(name:"MSKB", value:"4057116");
  script_xref(name:"MSKB", value:"4057117");
  script_xref(name:"MSKB", value:"4057118");
  script_xref(name:"MSKB", value:"4057119");
  script_xref(name:"MSKB", value:"4057120");
  script_xref(name:"MSKB", value:"4057121");
  script_xref(name:"MSKB", value:"4057122");
  script_xref(name:"MSKB", value:"4052987");
  script_xref(name:"MSKB", value:"4058559");
  script_xref(name:"MSKB", value:"4058560");

  script_name(english:"ADV180002: Microsoft SQL Server January 2018 Security Update (Meltdown) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by a vulnerability exists within microprocessors
utilizing speculative execution and indirect branch prediction,
which may allow an attacker with local user access to  disclose
information via a side-channel analysis.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/ADV180002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?573cb1ef");
  # https://support.microsoft.com/en-us/help/4057113/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a5c1225");
  # https://support.microsoft.com/en-us/help/4057114/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75a275b4");
  # https://support.microsoft.com/en-us/help/4057115/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e0fe7c6");
  # https://support.microsoft.com/en-us/help/4057116/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ba131b75");
  # https://support.microsoft.com/en-us/help/4057117/description-of-the-security-update-for-sql-server-2014-sp2-cu10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96a526af");
  # https://support.microsoft.com/en-us/help/4057118/description-of-the-security-update-for-sql-server-2016-sp1-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f305d4da");
  # https://support.microsoft.com/en-us/help/4057119/cumulative-update-7-for-sql-server-2016-sp1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97d419b3");
  # https://support.microsoft.com/en-us/help/4057120/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?17660a56");
  # https://support.microsoft.com/en-us/help/4057121/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4d20b7cb");
  # https://support.microsoft.com/en-us/help/4057122/description-of-the-security-update-for-sql-server-2017-gdr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df512157");
  # https://support.microsoft.com/en-us/help/4052987/cumulative-update-3-for-sql-server-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bce5a045");
  # https://support.microsoft.com/en-us/help/4058559/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?33d23aa9");
  # https://support.microsoft.com/en-us/help/4058560/security-update-for-vulnerabilities-in-sql-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?770a3f93");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2008, 2008 R2, 2012, 2014, 2016, and 2017.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-5754");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
  { # SP4 CU
    'product_version' : '2008',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2007.100.1000.0',
    'fixed_version'   : '2007.100.6556.23',
    'kb'              : '4057114'
  },
  { # SP3 CU
    'product_version' : '2008-R2',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2009.100.1000.0',
    'fixed_version'   : '2009.100.6560.0',
    'kb'              : '4057113'
  },
  { # RTM thru SP3 GDR
    'product_version' : '2012',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2011.110.2100.0',
    'fixed_version'   : '2011.110.6260.1',
    'kb'              : '4057115'
  },
  { # No GDR patch SP3 CU 
    'product_version' : '2012',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2011.110.6518.0',
    'fixed_version'   : '2011.110.6615.2',
    'kb'              : '4057121'
  },
  { # SP4 CU
    'product_version' : '2012',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2011.110.7001.0',
    'fixed_version'   : '2011.110.7462.6',
    'kb'              : '4057116'
  },
  { # SP2 GDR
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2014.120.5000.0',
    'fixed_version'   : '2014.120.5214.6',
    'kb'              : '4057120'
  },
  { # SP2 CU10
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.5563.0',
    'fixed_version'   : '2014.120.5571.0',
    'kb'              : '4052725'
  },
  { # SP1 GDR
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.4000.0',
    'fixed_version'   : '2015.130.4210.6',
    'kb'              : '4057118'
  },
  { # SP1 CU7
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.4400.0',
    'fixed_version'   : '2015.130.4466.4',
    'kb'              : '4058561'
  },
  { # GDR
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.1000.0',
    'fixed_version'   : '2015.130.1745.2',
    'kb'              : '4058560'
  },
  { # RTM CU
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.2000.0',
    'fixed_version'   : '2015.130.2218.0',
    'kb'              : '4058559'
  },
  { # RTM GDR
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2017.140.1000.0',
    'fixed_version'   : '2017.140.2000.63',
    'kb'              : '4057122'
  },
  { # RTM CU
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2017.140.3006.0',
    'fixed_version'   : '2017.140.3015.40',
    'kb'              : '4058562'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  severity          : SECURITY_WARNING
);

