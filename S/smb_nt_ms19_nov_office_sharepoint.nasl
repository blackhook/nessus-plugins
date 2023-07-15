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
  script_id(130914);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2019-1442",
    "CVE-2019-1443",
    "CVE-2019-1446",
    "CVE-2019-1491"
  );
  script_xref(name:"MSKB", value:"4484151");
  script_xref(name:"MSKB", value:"4484165");
  script_xref(name:"MSKB", value:"4484157");
  script_xref(name:"MSKB", value:"4484149");
  script_xref(name:"MSKB", value:"4484159");
  script_xref(name:"MSKB", value:"4484142");
  script_xref(name:"MSKB", value:"4484143");
  script_xref(name:"MSFT", value:"MS19-4484151");
  script_xref(name:"MSFT", value:"MS19-4484165");
  script_xref(name:"MSFT", value:"MS19-4484157");
  script_xref(name:"MSFT", value:"MS19-4484149");
  script_xref(name:"MSFT", value:"MS19-4484159");
  script_xref(name:"MSFT", value:"MS19-4484142");
  script_xref(name:"MSFT", value:"MS19-4484143");
  script_xref(name:"IAVA", value:"2019-A-0420-S");
  script_xref(name:"IAVA", value:"2020-A-0032-S");

  script_name(english:"Security Updates for Microsoft SharePoint Server (November 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A security feature bypass vulnerability exists when
    Microsoft Office does not validate URLs. An attacker
    could send a victim a specially crafted file, which
    could trick the victim into entering credentials. An
    attacker who successfully exploited this vulnerability
    could perform a phishing attack. The update addresses
    the vulnerability by ensuring Microsoft Office properly
    validates URLs. (CVE-2019-1442)

  - An information disclosure vulnerability exists in
    Microsoft SharePoint when an attacker uploads a
    specially crafted file to the SharePoint Server. An
    authenticated attacker who successfully exploited this
    vulnerability could potentially leverage SharePoint
    functionality to obtain SMB hashes. The security update
    addresses the vulnerability by correcting how SharePoint
    checks file content. (CVE-2019-1443)

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2019-1446)

  - An information disclosure vulnerability exists in
    Microsoft SharePoint when an attacker sends a specially
    crafted API request to the SharePoint Server. An
    authenticated attacker who successfully exploited this
    vulnerability could potentially read arbitrary files 
    on the server. The security update
    addresses the vulnerability by changing how 
    affected APIs process requests. (CVE-2019-1491)");
  # https://support.microsoft.com/en-us/help/4484151/security-update-for-sharepoint-server-2013-november-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?30239d3e");
  # https://support.microsoft.com/en-us/help/4484165/security-update-for-sharepoint-foundation-2010-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0fd61f92");
  # https://support.microsoft.com/en-us/help/4484157/security-update-for-sharepoint-foundation-2013-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7c4a9439");
  # https://support.microsoft.com/en-us/help/4484149/security-update-for-sharepoint-server-2019-language-pack-november-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c15982d");
  # https://support.microsoft.com/en-us/help/4484159/security-update-for-sharepoint-server-2010-november-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5fe30ea9");
  # https://support.microsoft.com/en-us/help/4484142/security-update-for-sharepoint-server-2019-november-12-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dbccec34");
  # https://support.microsoft.com/en-us/help/4484143/security-update-for-sharepoint-enterprise-server-2016-november-12
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9013241d");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484151
  -KB4484165
  -KB4484157
  -KB4484149
  -KB4484159
  -KB4484142
  -KB4484143");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1491");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    'edition'      : 'Server',
    'kb'           : '4484159',
    'path'         :  app_info.path,
    'version'      : '14.0.7241.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'edition'      : 'Foundation',
    'kb'           : '4484165',
    'path'         :  app_info.path,
    'version'      : '14.0.7241.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\web server extensions\14\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4484157',
    'path'         :  app_info.path,
    'version'      : '15.0.5189.1000',
    'append'       : "microsoft shared\web server extensions\15\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4484151',
    'path'         :  app_info.path,
    'version'      : '15.0.5189.1000',
    'append'       : "bin",
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4484143',
    'path'         :  app_info.path,
    'version'      : '16.0.4921.1000',
    'append'       : "transformapps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4484142',
    'path'         :  app_info.path,
    'version'      : '16.0.10352.20000',
    'append'       : "bin",
    'file'         : 'microsoft.sharepoint.publishing.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4484149',
    'path'         :  app_info.path,
    'version'      : '16.0.10352.20000',
    'append'       : "bin",
    'file'         : 'microsoft.sharepoint.publishing.intl.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-11',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
