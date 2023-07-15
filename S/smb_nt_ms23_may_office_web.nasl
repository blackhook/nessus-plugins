#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
##

include('compat.inc');

if (description)
{
  script_id(175336);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/16");

  script_cve_id("CVE-2023-24953");
  script_xref(name:"MSKB", value:"5002372");
  script_xref(name:"MSFT", value:"MS23-5002372");
  script_xref(name:"IAVA", value:"2023-A-0245-S");

  script_name(english:"Security Updates for Microsoft Office Online Server (May 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Web Apps installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Web Apps installation on the remote host is missing a security update. It is, therefore, affected
by the following vulnerability:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized
    arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002372");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB5002372 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-24953");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

var path, vuln;

var bulletin = 'MS23-05';
var kbs = make_list('5002372');


if (get_kb_item('Host/patch_management_checks')) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var port = kb_smb_transport();

# Get installs of Office Web Apps
var owa_installs = get_installs(app_name:'Microsoft Office Web Apps');

if (!empty_or_null(owa_installs))
{
  var owa_install;
  foreach owa_install (owa_installs[1])
  {
    if (owa_install['Product'] == '2013')
    {
      var owa_2013_path = owa_install['path'];
      var owa_2013_sp = owa_install['SP'];
    }
    else if (owa_install['Product'] == '2016')
    {
      var oos_path = owa_install['path'];
      var oos_sp = owa_install['SP'];
    }
  }
}
vuln = FALSE;

####################################################################
# Office Online Server
####################################################################
if (oos_path && (!isnull(oos_sp) && oos_sp == '0'))
{
  path = hotfix_append_path(path:oos_path, value:'WordConversionService\\bin\\Converter');
  if (hotfix_check_fversion(file:'sword.dll', version:'16.0.10398.20000', min_version:'16.0.10000.0', path:path, kb:'5002372', product:'Office Online Server') == HCF_OLDER)
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
