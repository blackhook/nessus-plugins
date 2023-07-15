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
  script_id(122155);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id(
    "CVE-2019-0594",
    "CVE-2019-0604",
    "CVE-2019-0668",
    "CVE-2019-0670"
  );
  script_bugtraq_id(
    106866,
    106894,
    106900,
    106914
  );
  script_xref(name:"MSKB", value:"4462155");
  script_xref(name:"MSKB", value:"4462143");
  script_xref(name:"MSKB", value:"4461630");
  script_xref(name:"MSKB", value:"4462139");
  script_xref(name:"MSKB", value:"4462171");
  script_xref(name:"MSFT", value:"MS19-4462155");
  script_xref(name:"MSFT", value:"MS19-4462143");
  script_xref(name:"MSFT", value:"MS19-4461630");
  script_xref(name:"MSFT", value:"MS19-4462139");
  script_xref(name:"MSFT", value:"MS19-4462171");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Sharepoint Server (February 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Sharepoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Sharepoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An elevation of privilege vulnerability exists when
    Microsoft SharePoint Server does not properly sanitize a
    specially crafted web request to an affected SharePoint
    server. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected SharePoint server. The attacker who
    successfully exploited the vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. These attacks could allow the attacker to read
    content that the attacker is not authorized to read, use
    the victim's identity to take actions on the SharePoint
    site on behalf of the user, such as change permissions
    and delete content, and inject malicious content in the
    browser of the user. The security update addresses the
    vulnerability by helping to ensure that SharePoint
    Server properly sanitizes web requests. (CVE-2019-0668)

  - A spoofing vulnerability exists in Microsoft SharePoint
    when the application does not properly parse HTTP
    content. An attacker who successfully exploited this
    vulnerability could trick a user by redirecting the user
    to a specially crafted website. The specially crafted
    website could either spoof content or serve as a pivot
    the chain an attach with other vulnerabilities in web
    services.  (CVE-2019-0670)

  - A remote code execution vulnerability exists in
    Microsoft SharePoint when the software fails to check
    the source markup of an application package. An attacker
    who successfully exploited the vulnerability could run
    arbitrary code in the context of the SharePoint
    application pool and the SharePoint server farm account.
    Exploitation of this vulnerability requires that a user
    uploads a specially crafted SharePoint application
    package to an affected versions of SharePoint. The
    security update addresses the vulnerability by
    correcting how SharePoint checks the source markup of
    application packages. (CVE-2019-0594, CVE-2019-0604)");
  # https://support.microsoft.com/en-us/help/4462155/description-of-the-security-update-for-sharepoint-enterprise-server
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?71efd273");
  # https://support.microsoft.com/en-us/help/4462143/description-of-the-security-update-for-sharepoint-foundation-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31759012");
  # https://support.microsoft.com/en-us/help/4461630/description-of-the-security-update-for-sharepoint-foundation-2010-febr
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?126ab229");
  # https://support.microsoft.com/en-us/help/4462139/description-of-the-security-update-for-sharepoint-server-2013-february
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08e6d248");
  # https://support.microsoft.com/en-us/help/4462171/description-of-the-security-update-for-sharepoint-server-2019-february
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?329d679a");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4462155
  -KB4462143
  -KB4461630
  -KB4462139
  -KB4462171");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0604");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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
    'edition'      : 'Foundation',
    'kb'           : '4461630',
    'path'         :  app_info.path,
    'version'      : '14.0.7229.5000',
    'min_version'  : '14.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\14\bin",
    'file'         : 'onetutil.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2010 SP2'
  },
  {
    'product'      : '2013',
    'edition'      : 'Server',
    'kb'           : '4462139',
    'path'         :  app_info.path,
    'version'      : '15.0.5103.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "TransformApps",
    'file'         : 'docxpageconverter.exe',
    'product_name' : 'Microsoft SharePoint Enterprise Server 2013 SP1'
  },
  {
    'product'      : '2013',
    'edition'      : 'Foundation',
    'kb'           : '4462143',
    'path'         :  app_info.path,
    'version'      : '15.0.5111.1000',
    'min_version'  : '15.0.0.0',
    'append'       : "microsoft shared\Web Server Extensions\15\bin",
    'file'         : 'csisrv.dll',
    'product_name' : 'Microsoft SharePoint Foundation Server 2013 SP1'
  },
  {
    'product'      : '2016',
    'edition'      : 'Server',
    'kb'           : '4462155',
    'path'         :  app_info.path,
    'version'      : '16.0.4810.1000',
    'min_version'  : '16.0.0.0',
    'append'       : "BIN",
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Server 2016'
  },
  {
    'product'      : '2019',
    'edition'      : 'Server',
    'kb'           : '4462171',
    'path'         :  app_info.path,
    'version'      : '16.0.10341.20000',
    'min_version'  : '16.0.0.0',
    'append'       : "BIN",
    'file'         : 'ascalc.dll',
    'product_name' : 'Microsoft SharePoint Server 2019'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS19-02',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
