#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101372);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/14");

  script_cve_id("CVE-2017-0243", "CVE-2017-8501", "CVE-2017-8569");
  script_bugtraq_id(99441, 99446, 99447);
  script_xref(name:"MSKB", value:"3191902");
  script_xref(name:"MSFT", value:"MS17-3191902");
  script_xref(name:"MSKB", value:"3203459");
  script_xref(name:"MSFT", value:"MS17-3203459");
  script_xref(name:"MSKB", value:"3213544");
  script_xref(name:"MSFT", value:"MS17-3213544");
  script_xref(name:"MSKB", value:"3213559");
  script_xref(name:"MSFT", value:"MS17-3213559");
  script_xref(name:"MSKB", value:"3213629");
  script_xref(name:"MSFT", value:"MS17-3213629");

  script_name(english:"Security Update for Microsoft SharePoint Server and Project Server (July 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server or Project Server installed on the
remote Windows host is missing a security update. It is, therefore,
affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    website or open a specially crafted document, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-0243)

  - A remote code execution vulnerability exists in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to visit a specially crafted
    website or open a specially crafted document, to
    execute arbitrary code in the context of the current
    user. (CVE-2017-8501)

  - A cross-site scripting (XSS) vulnerability exists in
    Microsoft SharePoint Server due improper validation of
    user-supplied input in web requests. An authenticated,
    remote attacker can exploit this, via a specially
    crafted request, to execute arbitrary script code in a
    user's browser session. (CVE-2017-8569)");
  # https://support.microsoft.com/eu-es/help/3191902/descriptionofthesecurityupdateforexcelservicesonsharepointserver2010ju
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?26d330c5");
  # https://support.microsoft.com/eu-es/help/3203459/descriptionofthesecurityupdateforsharepointserver2010july11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?085f59c5");
  # https://support.microsoft.com/en-us/help/3213544/descriptionofthesecurityupdateforsharepointserver2016july11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a76483b3");
  # https://support.microsoft.com/en-us/help/3213559/descriptionofthesecurityupdateforsharepointserver2013july11-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31828232");
  # https://support.microsoft.com/eu-es/help/3213629/july-11-2017-cumulative-update-for-project-server-2010-kb3213629
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4c8bed4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2013
and 2016; Excel Services on SharePoint Server 2010; and Microsoft
Project Server 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8501");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
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
    'kb'           : '3213544',
    'path'         :  app_info.path,
    'append'       : "WebServices\ConversionServices",
    'min_version'  : '16.0.0.0',
    'version'      : '16.0.4561.1000',
    'edition'      : 'Server',
    'file'         : 'sword.dll',
    'product_name' : 'Office SharePoint Server 2016'
  },
  {
    'product'      : '2013',
    'kb'           : '3213559',
    'path'         :  app_info.path,
    'append'       : "Bin",
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4945.1000',
    'edition'      : 'Server',
    'file'         : 'xlsrv.dll',
    'product_name' : 'Office SharePoint Server 2013 SP1'
  },
  {
    'product'      : '2010',
    'kb'           : '3213629',
    'path'         :  app_info.path,
    'append'       : "Bin",
    'min_version'  : '14.0.0.0',
    'version'      : '14.0.7183.5000',
    'edition'      : 'Server',
    'file'         : 'xlsrv.dll',
    'product_name' : 'Microsoft Project Server 2010 SP2'
  },
  {
    'product'      : '2010',
    'kb'           : '3203459',
    'path'         :  app_info.path,
    'min_version'  : '15.0.0.0',
    'version'      : '15.0.4569.1503',
    'file'         : 'mssp3gl.dll',
    'product_name' : 'SharePoint 2010 for Microsoft Business Productivity Servers'
  },
  {
    'product'      : '2010',
    'kb'           : '3191902',
    'path'         :  app_info.path,
    'min_version'  : '15.0.0.0',
    'version'      : '14.0.7183.5000',
    'edition'      : 'Server',
    'file'         : 'xlsrv.dll',
    'product_name' : 'Office SharePoint Server 2010 Excel Services'
  }
];
vcf::microsoft::sharepoint::check_version_and_report
(
  app_info:app_info, 
  bulletin:'MS17-07',
  constraints:kb_checks, 
  severity:SECURITY_HOLE
);
