#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(119686);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id(
    "CVE-2018-8580",
    "CVE-2018-8627",
    "CVE-2018-8628",
    "CVE-2018-8635",
    "CVE-2018-8650"
  );
  script_xref(name:"MSKB", value:"2965309");
  script_xref(name:"MSKB", value:"4092468");
  script_xref(name:"MSKB", value:"4092472");
  script_xref(name:"MSKB", value:"4461558");
  script_xref(name:"MSKB", value:"4461569");
  script_xref(name:"MSKB", value:"4461541");
  script_xref(name:"MSKB", value:"4461548");
  script_xref(name:"MSKB", value:"4461549");
  script_xref(name:"MSKB", value:"4461465");
  script_xref(name:"MSKB", value:"4461580");
  script_xref(name:"MSFT", value:"MS18-2965309");
  script_xref(name:"MSFT", value:"MS18-4092468");
  script_xref(name:"MSFT", value:"MS18-4092472");
  script_xref(name:"MSFT", value:"MS18-4461558");
  script_xref(name:"MSFT", value:"MS18-4461569");
  script_xref(name:"MSFT", value:"MS18-4461541");
  script_xref(name:"MSFT", value:"MS18-4461548");
  script_xref(name:"MSFT", value:"MS18-4461549");
  script_xref(name:"MSFT", value:"MS18-4461465");
  script_xref(name:"MSFT", value:"MS18-4461580");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (December 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Excel software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Excel software. The security update
    addresses the vulnerability by properly initializing the
    affected variable. (CVE-2018-8627)

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted authentication request to an affected
    SharePoint server. An attacker who successfully
    exploited this vulnerability could execute malicious
    code on a vulnerable server in the context of the
    SharePoint application pool account.  (CVE-2018-8635)

  - An information disclosure vulnerability exists where
    certain modes of the search function in Microsoft
    SharePoint Server are vulnerable to cross-site search
    attacks (a variant of cross-site request forgery, CSRF).
    When users are simultaneously logged in to Microsoft
    SharePoint Server and visit a malicious web page, the
    attacker can, through standard browser functionality,
    induce the browser to invoke search queries as the
    logged in user. While the attacker cant access the
    search results or documents as such, the attacker can
    determine whether the query did return results or not,
    and thus by issuing targeted queries discover facts
    about documents that are searchable for the logged-in
    user. The security update addresses the vulnerability by
    running the search queries in a way that doesnt expose
    them to this browser vulnerability. (CVE-2018-8580)

  - A remote code execution vulnerability exists in
    Microsoft PowerPoint software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8628)");
  # https://support.microsoft.com/en-us/help/4092472/descriptionofthesecurityupdateforsharepointenterpriseserver2013decembe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?70c99df5");
  # https://support.microsoft.com/en-us/help/4461569/descriptionofthesecurityupdateforsharepointserver2010december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00f6be56");
  # https://support.microsoft.com/en-us/help/4461558/descriptionofthesecurityupdateforsharepointfoundation2013december11201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4997c825");
  # https://support.microsoft.com/en-us/help/4461549/descriptionofthesecurityupdateforsharepointenterpriseserver2013decembe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fab3001");
  # https://support.microsoft.com/en-us/help/4461465/descriptionofthesecurityupdateforsharepointserver2010december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de9bd607");
  # https://support.microsoft.com/en-us/help/4461541/descriptionofthesecurityupdateforsharepointenterpriseserver2016decembe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e996ac3b");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB2965309
  -KB4092468
  -KB4092472
  -KB4461558
  -KB4461569
  -KB4461548
  -KB4461549
  -KB4461465
  -KB4461580
  -KB4461541");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8628");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-8635");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_microsoft.inc');

var app_info = vcf::microsoft::sharepoint::get_app_info();
var kb_checks = 
[
  {
    'product'      : '2010',
    'kb'           : '4461580',
    'path'         :  app_info.path,
    'edition'      : 'Foundation',
    'version'      : '14.0.7225.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\14\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'kb'           : '4461569',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7225.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "Bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2 (Excel Service)'
  },
  {
    'product'      : '2010',
    'kb'           : '4461465',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7225.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\14\ISAPI",
    'file'         : 'microsoft.sharepoint.portal.dll',
    'product_name' : 'Microsoft SharePoint Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'kb'           : '4461549',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5093.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'msoserver.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4092472',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5093.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'ppserver.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4461558',
    'path'         :  app_info.path,
    'edition'      : 'Foundation',
    'version'      : '15.0.5093.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\15\bin",
    'file'         : 'csisrv.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'kb'           : '4461541',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.4783.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'msoserver.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  },
  {
    'product'      : '2019',
    'kb'           : '4461548',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.10338.12107',
    'min_version'  : '16.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\16\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-12',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
