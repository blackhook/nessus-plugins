#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(126631);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id("CVE-2019-1068");
  script_bugtraq_id(108954);
  script_xref(name:"MSKB", value:"4505217");
  script_xref(name:"MSKB", value:"4505419");
  script_xref(name:"MSKB", value:"4505422");
  script_xref(name:"MSKB", value:"4505218");
  script_xref(name:"MSKB", value:"4505219");
  script_xref(name:"MSKB", value:"4505225");
  script_xref(name:"MSKB", value:"4505224");
  script_xref(name:"MSKB", value:"4505222");
  script_xref(name:"MSKB", value:"4505221");
  script_xref(name:"MSKB", value:"4505220");
  script_xref(name:"MSFT", value:"MS19-4505217");
  script_xref(name:"MSFT", value:"MS19-4505419");
  script_xref(name:"MSFT", value:"MS19-4505422");
  script_xref(name:"MSFT", value:"MS19-4505218");
  script_xref(name:"MSFT", value:"MS19-4505219");
  script_xref(name:"MSFT", value:"MS19-4505225");
  script_xref(name:"MSFT", value:"MS19-4505224");
  script_xref(name:"MSFT", value:"MS19-4505222");
  script_xref(name:"MSFT", value:"MS19-4505221");
  script_xref(name:"MSFT", value:"MS19-4505220");

  script_name(english:"Security Updates for Microsoft SQL Server (July 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SQL Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SQL Server installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft SQL Server when it incorrectly handles
    processing of internal functions. An attacker who
    successfully exploited this vulnerability could execute
    code in the context of the SQL Server Database Engine
    service account.  (CVE-2019-1068)");
  # https://support.microsoft.com/en-us/help/4505217/security-update-for-sql-server-2014-sp2-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a359a1a6");
  # https://support.microsoft.com/en-us/help/4505419/description-of-the-security-update-for-sql-server-2014-sp2-cu17-gdr-ju
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3515161a");
  # https://support.microsoft.com/en-us/help/4505422/security-update-for-sql-server-2014-sp3-cu3-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e525f475");
  # https://support.microsoft.com/en-us/help/4505218/description-of-the-security-update-for-sql-server-2014-sp3-gdr-july-9
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?619cf09c");
  # https://support.microsoft.com/en-us/help/4505219/security-update-for-sql-server-2016-sp1-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87d34b59");
  # https://support.microsoft.com/en-us/help/4505225/security-update-for-sql-server-2017-cu15-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2e915a50");
  # https://support.microsoft.com/en-us/help/4505224/description-of-the-security-update-for-sql-server-2017-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d9e5dfaf");
  # https://support.microsoft.com/en-us/help/4505222/security-update-for-sql-server-2016-sp2-cu7-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2a252018");
  # https://support.microsoft.com/en-us/help/4505221/description-of-the-security-update-for-sql-server-2016-sp1-cu15-gdr-ju
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?893cb218");
  # https://support.microsoft.com/en-us/help/4505220/security-update-for-sql-server-2016-sp2-gdr-july-9-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d42b7b26");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4505217
  -KB4505419
  -KB4505422
  -KB4505218
  -KB4505219
  -KB4505225
  -KB4505224
  -KB4505222
  -KB4505221
  -KB4505220");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2014.120.5000.0',
    'fixed_version'   : '2014.120.5223.6',
    'kb'              : '4505217'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2014.120.5300.0',
    'fixed_version'   : '2014.120.5659.1',
    'kb'              : '4505419'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2014.120.6100.0',
    'fixed_version'   : '2014.120.6108.1',
    'kb'              : '4505418'
  },
  {
    'product_version' : '2014',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2014.120.6200.0',
    'fixed_version'   : '2014.120.6293.0',
    'kb'              : '4505422'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.4000.0',
    'fixed_version'   : '2015.130.4259.0',
    'kb'              : '4505219'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64, x86',
    'file'            : 'setup.exe',
    'min_version'     : '2015.130.4400.0',
    'fixed_version'   : '2015.130.4466.4',
    'kb'              : '4505221'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.131.5000.0',
    'fixed_version'   : '2015.131.5101.9',
    'kb'              : '4505220'
  },
  {
    'product_version' : '2016',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2015.131.5250.0',
    'fixed_version'   : '2015.131.5366.0',
    'kb'              : '4505222'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2017.140.1000.0',
    'fixed_version'   : '2017.140.2021.2',
    'kb'              : '4505224'
  },
  {
    'product_version' : '2017',
    'target_hw'       : 'x64',
    'file'            : 'setup.exe',
    'min_version'     : '2017.140.3000.0',
    'fixed_version'   : '2017.140.3192.2',
    'kb'              : '4505225'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  severity          : SECURITY_WARNING
);
