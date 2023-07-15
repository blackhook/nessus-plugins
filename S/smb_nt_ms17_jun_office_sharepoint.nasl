#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(100787);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2017-8509",
    "CVE-2017-8511",
    "CVE-2017-8512",
    "CVE-2017-8513",
    "CVE-2017-8514",
    "CVE-2017-8551"
  );
  script_bugtraq_id(
    98812,
    98815,
    98816,
    98830,
    98831,
    98913
  );
  script_xref(name:"MSKB", value:"3127894");
  script_xref(name:"MSKB", value:"3172445");
  script_xref(name:"MSKB", value:"3203384");
  script_xref(name:"MSKB", value:"3203385");
  script_xref(name:"MSKB", value:"3203387");
  script_xref(name:"MSKB", value:"3203388");
  script_xref(name:"MSKB", value:"3203390");
  script_xref(name:"MSKB", value:"3203397");
  script_xref(name:"MSKB", value:"3203398");
  script_xref(name:"MSKB", value:"3203399");
  script_xref(name:"MSKB", value:"3203430");
  script_xref(name:"MSKB", value:"3203431");
  script_xref(name:"MSKB", value:"3203432");
  script_xref(name:"MSKB", value:"3203458");
  script_xref(name:"MSFT", value:"MS17-3127894");
  script_xref(name:"MSFT", value:"MS17-3172445");
  script_xref(name:"MSFT", value:"MS17-3203384");
  script_xref(name:"MSFT", value:"MS17-3203385");
  script_xref(name:"MSFT", value:"MS17-3203387");
  script_xref(name:"MSFT", value:"MS17-3203388");
  script_xref(name:"MSFT", value:"MS17-3203390");
  script_xref(name:"MSFT", value:"MS17-3203397");
  script_xref(name:"MSFT", value:"MS17-3203398");
  script_xref(name:"MSFT", value:"MS17-3203399");
  script_xref(name:"MSFT", value:"MS17-3203430");
  script_xref(name:"MSFT", value:"MS17-3203431");
  script_xref(name:"MSFT", value:"MS17-3203432");
  script_xref(name:"MSFT", value:"MS17-3203458");
  script_xref(name:"IAVA", value:"2017-A-0179-S");

  script_name(english:"Security Update for Microsoft SharePoint Server (June 2017)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installed on the remote Windows host
is missing a security update. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple remote code execution vulnerabilities exist in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these, by convincing a user to open a specially crafted
    document, to execute arbitrary code in the context of
    the current user. (CVE-2017-8509, CVE-2017-8511,
    CVE-2017-8512)

  - A remote code execution vulnerability exists in
    Microsoft PowerPoint due to improper handling of objects
    in memory. An unauthenticated, remote attacker can
    exploit this, by convincing a user to open a specially
    crafted file, to execute arbitrary code in the context
    of the current user. (CVE-2017-8513)

  - A reflective cross-site scripting (XSS) vulnerability
    exists in Microsoft SharePoint Server due improper
    validation of user-supplied input in web requests. An
    unauthenticated, remote attacker can exploit this, via a
    specially crafted request, to execute arbitrary script
    code in a user's browser session. (CVE-2017-8514)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize 
    a specially crafted web request to an affected
    SharePoint server. An authenticated attacker could
    exploit the vulnerability by sending a specially crafted
    request to an affected SharePoint server. (CVE-2017-8551)");
  script_set_attribute(attribute:"see_also", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007;
SharePoint Server 2010; SharePoint Enterprise Server 2013 and 2016;
SharePoint Foundation 2013; Word Automation Services on Microsoft
SharePoint Server 2010; and Microsoft Office Project Server 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8513");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_office_compatibility_pack_installed.nbin", "microsoft_project_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::sharepoint::get_app_info();
var kb_checks = 
[
  {
    'product'      : '2016',
    'kb'           : '3203432',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '16.0.0.0',
    'version'      : '16.0.4549.1000',
    'edition'      : 'Server',
    'file'         : 'sword.dll',
    'product_name' : 'SharePoint Enterprise Server 2016'
  },
  {
    'product'      : '2013',
    'kb'           : '3203399',
    'path'         :  app_info.path,
    'append'       : "Bin",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Server',
    'file'         : 'schedengine.exe',
    'product_name' : 'Microsoft Project Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203390',
    'path'         :  app_info.path,
    'append'       : "Bin",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4929.1000',
    'edition'      : 'Server',
    'file'         : 'xlsrv.dll',
    'product_name' : 'Office SharePoint Server 2013 Excel Services SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203431',
    'path'         :  app_info.path,
    'append'       : "Bin",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Server',
    'file'         : 'mssmsg.dll',
    'product_name' : 'SharePoint Foundation 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203384',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Server',
    'file'         : 'sword.dll',
    'product_name' : 'Office SharePoint Server 2013 Word Automation Services SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203397',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Server',
    'file'         : 'oartserver.dll',
    'product_name' : 'SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203387',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Server',
    'file'         : 'msoserver.dll',
    'product_name' : 'SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203388',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Server',
    'file'         : 'htmlutil.dll',
    'product_name' : 'SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3172445',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4741.1000',
    'edition'      : 'Server',
    'file'         : 'ppintl.dll',
    'product_name' : 'SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203398',
    'path'         :  app_info.path,
    'append'       : "BIN",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Foundation',
    'file'         : 'onetutil.dll',
    'product_name' : 'Office Sharepoint Foundation 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '3203385',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4937.1000',
    'edition'      : 'Foundation',
    'file'         : 'msoserver.dll',
    'product_name' : 'Office Sharepoint Foundation 2013 SP1'
  },
  {
    'product'      : '2010',
    'kb'           : '3203458',
    'path'         :  app_info.path,
    'append'       : "WebServices\WordServer\Core",
    'min_version'  : '14.0.0.0',
    'version'      : '14.0.7182.5000',
    'edition'      : 'Server',
    'file'         : 'sword.dll',
    'product_name' : 'Office SharePoint Server 2010 Word Automation Services SP2'
  },
  {
    'product'      : '2007',
    'kb'           : '3127894',
    'path'         :  app_info.path,
    'min_version'  : '12.0.0.0',
    'version'      : '12.0.6770.5000',
    'edition'      : 'Server',
    'file'         : 'ppcnv.dll',
    'product_name' : 'PowerPoint Compatability Pack SP3'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-06',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
