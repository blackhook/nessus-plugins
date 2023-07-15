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
  script_id(133620);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2020-0693", "CVE-2020-0694");
  script_xref(name:"MSKB", value:"4484255");
  script_xref(name:"MSKB", value:"4484259");
  script_xref(name:"MSKB", value:"4484264");
  script_xref(name:"MSFT", value:"MS20-4484255");
  script_xref(name:"MSFT", value:"MS20-4484259");
  script_xref(name:"MSFT", value:"MS20-4484264");

  script_name(english:"Security Updates for Microsoft SharePoint Server (February 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft SharePoint Server installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft SharePoint Server installation on the remote
host is missing security updates. It is, therefore, affected
by a cross-site scripting vulnerability. 

A cross-site-scripting (XSS) vulnerability exists when
Microsoft SharePoint Server does not properly sanitize a
specially crafted web request to an affected SharePoint
server. An authenticated attacker could exploit the
vulnerability by sending a specially crafted request to
an affected SharePoint server. The attacker who
successfully exploited the vulnerability could then
perform cross-site scripting attacks on affected systems
and run script in the security context of the current
user. The attacks could allow the attacker to read
content that the attacker is not authorized to read, use
the victim's identity to take actions on the SharePoint
site on behalf of the user, such as change permissions
and delete content, and inject malicious content in the
browser of the user. The security update addresses the
vulnerability by helping to ensure that SharePoint
Server properly sanitizes web requests. 
(CVE-2020-0693, CVE-2020-0694)");
  # https://support.microsoft.com/en-us/help/4484259/security-update-for-sharepoint-server-2019-february-11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?06155353");
  # https://support.microsoft.com/en-us/help/4484264/security-update-for-sharepoint-foundation-2013-feb-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1bcfb718");
  # https://support.microsoft.com/en-us/help/4484255/security-update-for-sharepoint-enterprise-server-2016-february-11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ab9bc90");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484255
  -KB4484259
  -KB4484264");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0694");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');
include('lists.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-02';

kbs = make_list(
  '4484264', # 2013 SP1 Foundation
  '4484255', # 2016 Enterprise
  '4484259' # 2019
);

if (get_kb_item('Host/patch_management_checks'))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, 'Failed to determine the location of %windir%.');

registry_init();

install = get_single_install(app_name:'Microsoft SharePoint Server');

kb_checks =
{
  '2013':
  { '1':
    {'Foundation':
      [{
        'kb': '4484264',
        'path': hotfix_get_commonfilesdir(),
        'append':'microsoft shared\\web server extensions\\15\\bin',
        'file':'onetutil.dll', 
        'version':'15.0.5215.1000',
        'product_name':'Microsoft SharePoint Foundation Server 2013 SP1'
      }]
    }
  },
  '2016':
  { '0':
    {'Server':
      [{
        'kb': '4484255',
        'path': install['path'],
        'append':'webservices\\conversionservices\\',
        'file':'sword.dll',
        'version':'16.0.4966.1000',
        'product_name':'Microsoft SharePoint Enterprise Server 2016'
      }]
    }
  },
  '2019': 
  { '0':
    {'Server':
      [{
        'kb': '4484259',
        'path': install['path'],
        'append':'webservices\\conversionservices\\',
        'file':'sword.dll',
        'version':'16.0.10355.20000',
        'product_name':'Microsoft SharePoint Server 2019'
      }]
    }
  }
};

# get the specific product / path 
param_list = kb_checks[install['Product']][install['SP']][install['Edition']];

# audit if not affected
if(isnull(param_list)) audit(AUDIT_INST_VER_NOT_VULN, "Microsoft SharePoint Server");

vuln = FALSE;
# grab the path otherwise
foreach check (param_list)
{
  path = hotfix_append_path(path:check['path'], value:check['append']);
  are_we_vuln = hotfix_check_fversion(file:check['file'], version:check['version'], path:path, kb:check['kb'], product:check['product_name']);
  if (are_we_vuln == HCF_OLDER)
  {
    vuln = TRUE;
  }
}

if (vuln == TRUE)
{
  port = kb_smb_transport();
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  if (xss) replace_kb_item(name:'www/' + port + '/XSS', value:TRUE);
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
