#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include("compat.inc");

if (description)
{
  script_id(111697);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/12");

  script_cve_id("CVE-2018-8378");
  script_xref(name:"MSKB", value:"4022234");
  script_xref(name:"MSKB", value:"4018392");
  script_xref(name:"MSKB", value:"4032215");
  script_xref(name:"MSKB", value:"4022236");
  script_xref(name:"MSKB", value:"4032256");
  script_xref(name:"MSFT", value:"MS18-4022234");
  script_xref(name:"MSFT", value:"MS18-4018392");
  script_xref(name:"MSFT", value:"MS18-4032215");
  script_xref(name:"MSFT", value:"MS18-4022236");
  script_xref(name:"MSFT", value:"MS18-4032256");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (August 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2018-8378)");
  # https://support.microsoft.com/en-us/help/4022234/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e0c11923");
  # https://support.microsoft.com/en-us/help/4018392/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f888033a");
  # https://support.microsoft.com/en-us/help/4032215/description-of-the-security-update-for-sharepoint-server-2010-august
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0961289a");
  # https://support.microsoft.com/en-us/help/4022236/description-of-the-security-update-for-sharepoint-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80a7ca85");
  # https://support.microsoft.com/en-us/help/4032256/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8e152f70");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4022234
  -KB4018392
  -KB4032215
  -KB4022236
  -KB4032256");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8378");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/14");

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
    'kb'           : '4032215',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '14.0.7211.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Word Automation Services'
  },
  {
    'product'      : '2013',
    'kb'           : '4022236',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5059.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'msoserver.dll',
    'product_name' : 'Microsoft SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4018392',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5053.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\ConversionServices",
    'file'         : 'ppserver.dll',
    'product_name' : 'Microsoft SharePoint Enterprise 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4022234',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '15.0.5059.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "WebServices\WordServer\Core",
    'file'         : 'sword.dll',
    'product_name' : 'Microsoft SharePoint Enterprise 2013 SP1'
  },
  {
    'product'      : '2013',
    'kb'           : '4032256',
    'path'         :  app_info.path,
    'edition'      : 'Server',
    'version'      : '16.0.4732.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\16\BIN",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2016'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS18-08',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
