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
  script_id(133621);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/03/13");

  script_cve_id("CVE-2020-0695");
  script_xref(name:"MSKB", value:"4484254");
  script_xref(name:"MSFT", value:"MS20-4484254");

  script_name(english:"Security Updates for Microsoft Office Online Server (February 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Online Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server installation on the
remote host is missing a security update. It is, therefore,
affected by the following vulnerability :

  - A spoofing vulnerability exists when Office Online
    Server does not validate origin in cross-origin
    communications correctly. An attacker could exploit the
    vulnerability by sending a specially crafted request to
    an affected site. The attacker who successfully
    exploited the vulnerability could then perform cross-
    origin attacks on affected systems. These attacks could
    allow the attacker to read content that the attacker is
    not authorized to read, and use the victim's identity to
    take actions on the site on behalf of the victim. The
    victim needs to be authenticated for an attacker to
    compromise the victim. The security update addresses the
    vulnerability by ensuring that Office Online Server
    properly validates origins. (CVE-2020-0695)");
  # https://support.microsoft.com/en-us/help/4484254/security-update-for-office-online-server-february-11-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3313a689");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4484254 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS20-02';
kbs = make_list('4484254');
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
  if (hotfix_check_fversion(file:'xlsrv.dll', version:'16.0.10355.20000', min_version:'16.0.0.0', path:path, kb:'4484254', product:'Office Online Server') == HCF_OLDER)
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

