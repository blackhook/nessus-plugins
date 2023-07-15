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
  script_id(146333);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id(
    "CVE-2021-24067",
    "CVE-2021-24068",
    "CVE-2021-24069",
    "CVE-2021-24070"
  );
  script_xref(name:"MSKB", value:"4493192");
  script_xref(name:"MSKB", value:"4493204");
  script_xref(name:"MSFT", value:"MS21-4493192");
  script_xref(name:"MSFT", value:"MS21-4493204");
  script_xref(name:"IAVA", value:"2021-A-0068-S");

  script_name(english:"Security Updates for Microsoft Office Online Server and Microsoft Office Web Apps (February 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Online Server or Microsoft Office Web Apps installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Online Server or Microsoft Office Web
Apps installation on the remote host is missing security
updates. It is, therefore, affected by multiple
vulnerabilities:

  - A remote code execution vulnerability. An attacker can
    exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2021-24067,
    CVE-2021-24068, CVE-2021-24069, CVE-2021-24070)");
  # https://support.microsoft.com/en-us/office/description-of-the-security-update-for-office-web-apps-server-2013-february-9-2021-kb4493204-769c7a3a-7092-6dbc-4556-b3457ceebbcf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18e53415");
  # https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-office-online-server-february-9-2021-kb4493192-4930dbe2-17f9-42d1-4174-3e281a746c84
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7362c0e1");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4493192
  -KB4493204");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-24070");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_online_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = 'MS21-02';

kbs = make_list('4493192', '4493204');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

port = kb_smb_transport();

# Get installs of Office Web Apps
owa_installs = get_installs(app_name:'Microsoft Office Web Apps');

if (!empty_or_null(owa_installs))
{
  foreach owa_install (owa_installs[1])
  {
    if (owa_install['Product'] == '2013')
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
# Office Web Apps 2013 SP1
####################################################################
if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == '1'))
{
  path = hotfix_append_path(path:owa_2013_path, value:'WordConversionService\\bin\\Converter');
  if (hotfix_check_fversion(file:'sword.dll', version:'15.0.5319.1000', min_version:'15.0.0.0', path:path, kb:'4493204', product:'Office Web Apps 2013') == HCF_OLDER)
    vuln = TRUE;
}

####################################################################
# Office Online Server
####################################################################
if (oos_path && (!isnull(oos_sp) && oos_sp == '0'))
{
  path = hotfix_append_path(path:oos_path, value:'WordConversionService\\bin\\Converter');
  if (hotfix_check_fversion(file:'sword.dll', version:'16.0.10370.20000', min_version:'16.0.0.0', path:path, kb:'4493192', product:'Office Online Server') == HCF_OLDER)
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
