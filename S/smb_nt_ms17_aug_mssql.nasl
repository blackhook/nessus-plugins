#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102271);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2017-8516");
  script_bugtraq_id(100041);
  script_xref(name:"MSKB", value:"4036996");
  script_xref(name:"MSKB", value:"4032542");
  script_xref(name:"MSKB", value:"4019095");
  script_xref(name:"MSKB", value:"4019093");
  script_xref(name:"MSKB", value:"4019092");
  script_xref(name:"MSKB", value:"4019091");
  script_xref(name:"MSKB", value:"4019090");
  script_xref(name:"MSKB", value:"4019089");
  script_xref(name:"MSKB", value:"4019088");
  script_xref(name:"MSKB", value:"4019086");
  script_xref(name:"MSFT", value:"MS17-4036996");
  script_xref(name:"MSFT", value:"MS17-4032542");
  script_xref(name:"MSFT", value:"MS17-4019095");
  script_xref(name:"MSFT", value:"MS17-4019093");
  script_xref(name:"MSFT", value:"MS17-4019092");
  script_xref(name:"MSFT", value:"MS17-4019091");
  script_xref(name:"MSFT", value:"MS17-4019090");
  script_xref(name:"MSFT", value:"MS17-4019089");
  script_xref(name:"MSFT", value:"MS17-4019088");
  script_xref(name:"MSFT", value:"MS17-4019086");

  script_name(english:"KB4036996: Security Update for SQL Server (August 2017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by an information disclosure vulnerability in
Microsoft SQL Server Analysis Services when it improperly enforces
permissions. An attacker could exploit the vulnerability if the
attacker's credentials allow access to an affected SQL server
database. An attacker who successfully exploited the vulnerability
could gain additional database and file information.");
  # https://support.microsoft.com/en-us/help/4036996/description-of-the-security-update-for-sql-server-2014-service-pack-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfd0b897");
  # https://support.microsoft.com/en-us/help/4032542/description-of-the-security-update-for-sql-server-2014-service-pack-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36cb4e99");
  # https://support.microsoft.com/en-us/help/4019095/description-of-the-security-update-for-sql-server-2016-service-pack-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6f68e083");
  # https://support.microsoft.com/en-us/help/4019093/description-of-the-security-update-for-sql-server-2014-service-pack-2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d9d929f");
  # https://support.microsoft.com/en-us/help/4019092/description-of-the-security-update-for-sql-server-2012-service-pack-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?437909d8");
  # https://support.microsoft.com/en-us/help/4019091/description-of-the-security-update-for-sql-server-2014-service-pack-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5cf8885b");
  # https://support.microsoft.com/en-us/help/4019090/description-of-the-security-update-for-sql-server-2012-service-pack-3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?84700f7c");
  # https://support.microsoft.com/en-us/help/4019089/description-of-the-security-update-for-sql-server-2016-service-pack-1%22
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7d95d0aa");
  # https://support.microsoft.com/en-us/help/4019088/description-of-the-security-update-for-sql-server-2016-rtm-gdr-august
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?36082fe7");
  # https://support.microsoft.com/en-us/help/4019086/description-of-the-security-update-for-sql-server-2016-rtm-cu-august-8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?180dfb8a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2012, 2014, and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "mssql_version.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl", "smb_enum_softwares.nasl");
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
    'min_version'     : '2011.110.6020.0',
    'fixed_version'   : '2011.110.6251.0',
    'kb'              : '4019092'
  },
  {
    'product_version' : '2012',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2011.110.6518.0',
    'fixed_version'   : '2011.110.6607.0',
    'kb'              : '4019090'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.4100.0',
    'fixed_version'   : '2014.120.4237.0',
    'kb'              : '4019091'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.4416.0',
    'fixed_version'   : '2014.120.4522.0',
    'kb'              : '4032542'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.5000.0',
    'fixed_version'   : '2014.120.5207.0',
    'kb'              : '4019093'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2014.120.5511.0',
    'fixed_version'   : '2014.120.5553.0',
    'kb'              : '4036996'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.130.2149.0',
    'fixed_version'   : '2015.130.2210.0',
    'kb'              : '4019086'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.130.1601.0',
    'fixed_version'   : '2015.130.1742.0',
    'kb'              : '4019088'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.130.4000.0',
    'fixed_version'   : '2015.130.4206.0',
    'kb'              : '4019089'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'sqlservr.exe',
    'min_version'     : '2015.130.4411.0',
    'fixed_version'   : '2015.130.4446.0',
    'kb'              : '4019095'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  severity          : SECURITY_WARNING
);