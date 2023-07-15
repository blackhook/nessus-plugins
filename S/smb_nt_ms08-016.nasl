#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31415);
 script_version("1.48");
 script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/28");
 script_cve_id("CVE-2007-1747", "CVE-2008-0113", "CVE-2008-0118");
 script_bugtraq_id(23826, 28146);
 script_xref(name:"CERT", value:"853184");
 script_xref(name:"MSFT", value:"MS08-016");
 script_xref(name:"MSKB", value:"947355");
 script_xref(name:"MSKB", value:"947361");
 script_xref(name:"MSKB", value:"947866");

 script_name(english:"MS08-016: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (949030)");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Office that is
subject to various flaws that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it with Microsoft Office.");
 # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-016
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8a0b1011");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2000, XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-1747");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_cwe_id(94, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS08-016';
var kbs = make_list('947355', '947361', '947866');

if (get_kb_item('Host/patch_management_checks')) 
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var vuln = FALSE;
var port = kb_smb_transport();

var office_vers = hotfix_check_office_version();
var office_sp, prod, path, kb, file, version;

# Office 2000 SP3
# Checking mso9.dll
if (office_vers['9.0'])
{
  office_sp = get_kb_item('SMB/Office/2000/SP');
  if (!isnull(office_sp) && office_sp == 3)
  {
    prod = 'Microsoft Office 2000 SP3';
    path = hotfix_get_officeprogramfilesdir(officever:'9.0');
    path = hotfix_append_path(path:path, value:"\Microsoft Office\Office");
    kb = '947361';
    file = 'mso9.dll';
    version = '9.0.0.8968';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office XP SP3
# Not checking ietag.dll, cannot verify file location
if (office_vers['10.0'])
{
  office_sp = get_kb_item('SMB/Office/XP/SP');
  if (!isnull(office_sp) && office_sp == 3)
  {
    prod = 'Microsoft Office XP SP3';
    path = hotfix_get_officecommonfilesdir(officever:'10.0');
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office10");
    kb = '947866';
    file = 'mso.dll';
    version = '10.0.6839.0';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
  }
}

# Office 2003 SP2
# Not checking ietag.dll, cannot verify file location
if (office_vers['11.0'])
{
  office_sp = get_kb_item('SMB/Office/2003/SP');
  if (!isnull(office_sp) && office_sp == 2)
  {
    prod = 'Microsoft Office 2003 SP2';
    path = hotfix_get_officecommonfilesdir(officever:'11.0');
    path = hotfix_append_path(path:path, value:"Microsoft Shared\Office11");
    kb = '947355';
    file = 'mso.dll';
    version = '11.0.8202.0';
    if (hotfix_check_fversion(file:file, version:version, path:path, kb:kb, bulletin:bulletin, product:prod) == HCF_OLDER )
      vuln = TRUE;
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

