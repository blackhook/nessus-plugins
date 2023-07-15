#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81270);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/25");

  script_cve_id("CVE-2015-0012");
  script_bugtraq_id(72473);
  script_xref(name:"MSFT", value:"MS15-017");
  script_xref(name:"MSKB", value:"3023195");
  script_xref(name:"MSKB", value:"3023914");
  script_xref(name:"IAVA", value:"2015-A-0036");

  script_name(english:"MS15-017: Vulnerability in Virtual Machine Manager Could Allow Elevation of Privilege (3035898)");
  script_summary(english:"Checks version of VirtualMachineViewer.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft System
Center Virtual Machine Manager that is affected by privilege
escalation vulnerability due to improper validation of user roles. An
attacker with valid Active Directory logon credentials can exploit
this vulnerability to gain administrative privileges.");
  script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2015/ms15-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Microsoft System Center Virtual
Machine Manager 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0012");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:virtual_machine_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_scvmm_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-017';

kbs = make_list(3023195, 3023914);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

app_name = 'Microsoft System Center Virtual Machine Manager';
get_install_count(app_name:app_name, exit_if_zero:TRUE);
install = get_single_install(app_name:app_name);

path = install['path'];
version = install['version'];

# This update applies to 2012 R2 U4 and above
if(ver_compare(ver:version, fix:'3.2.7768.0', strict:FALSE) == -1)
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);

vuln = FALSE;
bin_path = hotfix_append_path(path:path,value:"bin");

if (
  hotfix_check_fversion(file:"VirtualMachineViewer.exe",version:"3.2.7895.0",path:bin_path,bulletin:bulletin,kb:'3023914',product:app_name+" 2012 R2")==HCF_OLDER ||
  hotfix_check_fversion(file:"VirtualMachineViewer.exe",version:"3.2.7895.0",path:bin_path,bulletin:bulletin,kb:'3023195',product:app_name+" 2012 R2")==HCF_OLDER
) vuln = TRUE;

if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
