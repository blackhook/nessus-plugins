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
  script_id(138469);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/14");

  script_cve_id(
    "CVE-2020-1342",
    "CVE-2020-1442",
    "CVE-2020-1445",
    "CVE-2020-1446",
    "CVE-2020-1447",
    "CVE-2020-1448"
  );
  script_xref(name:"MSKB", value:"4484357");
  script_xref(name:"MSKB", value:"4484381");
  script_xref(name:"MSKB", value:"4484451");
  script_xref(name:"MSFT", value:"MS20-4484357");
  script_xref(name:"MSFT", value:"MS20-4484381");
  script_xref(name:"MSFT", value:"MS20-4484451");
  script_xref(name:"IAVA", value:"2020-A-0307-S");

  script_name(english:"Security Updates for Microsoft Office Web Apps (July 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Web Apps installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Web Apps installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Office improperly discloses the contents of
    its memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2020-1445)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2020-1446,
    CVE-2020-1447, CVE-2020-1448)

  - A spoofing vulnerability exists when an Office Web Apps
    server does not properly sanitize a specially crafted
    request. An authenticated attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected Office Web Apps server. The attacker who
    successfully exploited this vulnerability could then
    perform cross-site scripting attacks on affected systems
    and run script in the security context of the current
    user. For the vulnerability to be exploited, a user must
    click a specially crafted URL that takes the user to a
    targeted Office Web App site.  (CVE-2020-1442)

  - An information disclosure vulnerability exists when
    Microsoft Office software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Office software. The security
    update addresses the vulnerability by properly
    initializing the affected variable. (CVE-2020-1342)");
  # https://support.microsoft.com/en-us/help/4484357/security-update-for-office-web-apps-server-2013-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1ce2dd72");
  # https://support.microsoft.com/en-us/help/4484381/security-update-for-sharepoint-2010-office-web-apps-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?42ba0628");
  # https://support.microsoft.com/en-us/help/4484451/security-update-for-office-online-server-july-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cce850ff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4484357
  -KB4484381
  -KB4484451");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS20-07';
kbs = make_list(
  '4484357',
  '4484381',
  '4484451'
);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

# Get installs of Office Web Apps
owa_installs = get_installs(app_name:'Microsoft Office Web Apps');

if (!empty_or_null(owa_installs))
{
  foreach owa_install (owa_installs[1])
  {
    if (owa_install['Product'] == '2010')
    {
      owa_2010_path = owa_install['path'];
      owa_2010_sp = owa_install['SP'];
    }
    else if (owa_install['Product'] == '2013')
    {
      owa_2013_path = owa_install['path'];
      owa_2013_sp = owa_install['SP'];
    }
    else if (owa_install['Product'] == '2016')
    {
      oos_path = owa_install['path'];
      oos_sp = owa_install['SP'];
    }
  }
}
vuln = FALSE;

####################################################################
# Office Web Apps 2010 SP2
####################################################################
if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == '2'))
{
  path = hotfix_append_path(path:owa_2010_path, value:'14.0\\WebServices\\ConversionService\\Bin\\Converter');
  if (hotfix_check_fversion(file:'msoserver.dll', version:'14.0.7252.5000', min_version:'14.0.0.0', path:path, kb:'4484381', product:'Office Web Apps 2010') == HCF_OLDER)
    vuln = TRUE;
}

####################################################################
# Office Web Apps 2013 SP1
####################################################################
if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == '1'))
{
  path = hotfix_append_path(path:owa_2013_path, value:'WordConversionService\\bin\\Converter');
  if (hotfix_check_fversion(file:'sword.dll', version:'15.0.5259.1000', min_version:'15.0.0.0', path:path, kb:'4484357', product:'Office Web Apps 2013') == HCF_OLDER)
    vuln = TRUE;
}


####################################################################
# Office Online Server
####################################################################
if (oos_path && (!isnull(oos_sp) && oos_sp == '0'))
{
  path = hotfix_append_path(path:oos_path, value:'WordConversionService\\bin\\Converter');
  if (hotfix_check_fversion(file:'sword.dll', version:'16.0.10362.20000', min_version:'16.0.0.0', path:path, kb:'4484451', product:'Office Online Server') == HCF_OLDER)
    vuln = TRUE;
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}

