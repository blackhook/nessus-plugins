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
  script_id(129885);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value: "2020/03/13");

  script_cve_id("CVE-2019-1331");
  script_xref(name:"MSKB", value:"4475595");
  script_xref(name:"MSFT", value:"MS19-4475595");

  script_name(english:"Security Updates for Microsoft Office Online Server (October 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Online Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server installation on the remote host is missing a security update. It is, therefore, 
affected by a remote code execution vulnerability in Microsoft Excel software when the software fails to properly 
handle objects in memory. An attacker who successfully exploited the vulnerability could run arbitrary code in the 
context of the current user. If the current user is logged on with administrative user rights, an attacker could take 
control of the affected system. An attacker could then install programs; view, change, or delete data; or create new 
accounts with full user rights.");
  # https://support.microsoft.com/en-us/help/4475595/security-update-for-office-online-server-october-8-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3089fa2a");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of Office Online Server and apply the KB4475595 patch to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS19-10';
kbs = make_list('4475595');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

# Get installs of Office Web Apps
owa_installs = get_installs(app_name:'Microsoft Office Web Apps');

if (!empty_or_null(owa_installs))
{
  foreach owa_install (owa_installs[1])
  {
    if (owa_install['Product'] == '2016')
    {
      oos_path = owa_install['path'];
      oos_sp = owa_install['SP'];
    }
  }
}
vuln = FALSE;

####################################################################
# Office Online Server
####################################################################
if (oos_path && (!isnull(oos_sp) && oos_sp == '0'))
{
  path = hotfix_append_path(path:oos_path, value:"ExcelServicesEcs\bin");
  if (hotfix_check_fversion(file:'xlsrv.dll', version:'16.0.10351.20000', min_version:'16.0.0.0', path:path, kb:'4475595', product:'Office Online Server') == HCF_OLDER)
  vuln = TRUE;
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
