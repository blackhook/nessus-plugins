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
  script_id(130260);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2019-1034", "CVE-2019-1035");
  script_bugtraq_id(109156, 109373);
  script_xref(name:"MSKB", value:"4461621");
  script_xref(name:"MSKB", value:"4475511");
  script_xref(name:"MSFT", value:"MS19-4461621");
  script_xref(name:"MSFT", value:"MS19-4475511");
  script_xref(name:"CEA-ID", value:"CEA-2019-0430");

  script_name(english:"Security Updates for Microsoft Office Web Apps / Office Online Server (June 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Web Apps installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Web Apps installation or Office Online Server
installation on the remote host is missing security updates. It is,
therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2019-1034,
    CVE-2019-1035)");
  # https://support.microsoft.com/en-us/help/4461621/security-update-for-sharepoint-server-2010-office-web-apps-june-11-201
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d135b0d7");
  # https://support.microsoft.com/en-us/help/4475511/security-update-for-office-online-server-june-11-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c24f3182");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461621
  -KB4475511");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1034");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('misc_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS19-06';
kbs = make_list(
  '4461621', # Office Web Apps 2010
  '4475511'  # Office Online Server
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

# Get installs of Office Web Apps
owa_installs = get_installs(app_name:'Microsoft Office Web Apps');
vuln= FALSE;
if (!empty_or_null(owa_installs))
{
  foreach owa_install (owa_installs[1])
  {
    ####################################################################
    # Office Web Apps 2010 SP2
    ####################################################################
    if (owa_install['Product'] == '2010' && owa_install['path'] && (!isnull(owa_install['SP'])) && owa_install['SP'] =='2')
    {
      path = hotfix_append_path(path:owa_install['path'], value:"14.0\WebServices\ConversionService\Bin\Converter");
      if (hotfix_check_fversion(file:'msoserver.dll', version:'14.0.7229.5000', min_version:'14.0.0.0', path:path, kb:'4461621', product:'Office Web Apps 2010') == HCF_OLDER)
        vuln = TRUE;
    }
    ######################################################################
    # Office Online Server (2016)
    ######################################################################
    else if (owa_install['Product'] == '2016' && owa_install['path'] && (!isnull(owa_install['SP'])) && owa_install['SP'] =='0')
    {
      path = hotfix_append_path(path:owa_install['path'], value:"WordConversionService\bin\Converter");
      if (hotfix_check_fversion(file:'sword.dll', version:'16.0.10346.20001', min_version:'16.0.6000.0', path:path, kb:'4475511', product:'Office Online Server') == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

if (vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
