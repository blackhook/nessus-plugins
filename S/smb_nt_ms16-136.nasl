#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(94637);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/29");

  script_cve_id(
    "CVE-2016-7249",
    "CVE-2016-7250",
    "CVE-2016-7251",
    "CVE-2016-7252",
    "CVE-2016-7253",
    "CVE-2016-7254"
  );
  script_bugtraq_id(
    94037,
    94043,
    94050,
    94056,
    94060,
    94061
  );
  script_xref(name:"MSFT", value:"MS16-136");
  script_xref(name:"MSKB", value:"3194714");
  script_xref(name:"MSKB", value:"3194716");
  script_xref(name:"MSKB", value:"3194717");
  script_xref(name:"MSKB", value:"3194718");
  script_xref(name:"MSKB", value:"3194719");
  script_xref(name:"MSKB", value:"3194720");
  script_xref(name:"MSKB", value:"3194721");
  script_xref(name:"MSKB", value:"3194722");
  script_xref(name:"MSKB", value:"3194724");
  script_xref(name:"MSKB", value:"3194725");

  script_name(english:"MS16-136: Security Update for SQL Server (3199641)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SQL server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Microsoft SQL Server is missing a security update. It is,
therefore, affected by multiple vulnerabilities :

  - Multiple elevation of privilege vulnerabilities exist
    in the SQL RDBMS Engine due to improper handling of
    pointer casting. An authenticated, remote attacker can
    exploit these to gain elevated privileges.
    (CVE-2016-7249, CVE-2016-7250, CVE-2016-7254)

  - A cross-site scripting (XSS) vulnerability exists in
    the SQL server MDS API due to improper validation of a
    request parameter on the SQL server site. An
    unauthenticated, remote attacker can exploit this, via
    a specially crafted request, to execute arbitrary code
    in the user's browser session. (CVE-2016-7251)

  - An information disclosure vulnerability exists in
    Microsoft SQL Analysis Services due to improper
    validation of the FILESTREAM path. An authenticated,
    remote attacker can exploit this to disclose sensitive
    database and file information. (CVE-2016-7252)

  - An elevation of privilege vulnerability exists in the
    Microsoft SQL Server Engine due to improper checking by
    the SQL Server Agent of ACLs on atxcore.dll. An
    authenticated, remote attacker can exploit this to gain
    elevated privileges. (CVE-2016-7253)");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2016/ms16-136
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7fef1e99");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SQL Server 2012, 2014, and
2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7254");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sql_server");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'product_version': '2012',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2011.110.5058.0',
    'fixed_version':'2011.110.5388.0',
    'kb':'3194719'
  },
  {
    'product_version': '2012',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2011.110.5500.0',
    'fixed_version':'2011.110.5676.0',
    'kb':'3194725'
  },
  {
    'product_version': '2012',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2011.110.6020.0',
    'fixed_version':'2011.110.6248.0',
    'kb':'3194721'
  },
  {
    'product_version': '2012',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2011.110.6300.0',
    'fixed_version':'2011.110.6567.0',
    'kb':'3194724'
  },
  {
    'product_version': '2014',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2014.120.4100.0',
    'fixed_version':'2014.120.4232.0',
    'kb':'3194720'
  },
  {
    'product_version': '2014',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2014.120.4400.0',
    'fixed_version':'2014.120.4487.0',
    'kb':'3194722'
  },
  {
    'product_version': '2014',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2014.120.5000.0',
    'fixed_version':'2014.120.5203.0',
    'kb':'3194714'
  },
  {
    'product_version': '2014',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2014.120.5400.0',
    'fixed_version':'2014.120.5532.0',
    'kb':'3194718'
  },
  {
    'product_version': '2016',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2015.130.1601.5',
    'fixed_version':'2015.130.1722.0',
    'kb':'3194716'
  },
  {
    'product_version': '2016',
    'target_hw': 'x64, x86',
    'file': 'sqlservr.exe',
    'min_version': '2015.130.2100.0',
    'fixed_version':'2015.130.2186.6',
    'kb':'3194717'
  }
];

vcf::microsoft::mssql::check_version_and_report(
  app_info          : app_info,
  constraints       : constraints,
  severity          : SECURITY_WARNING
);
