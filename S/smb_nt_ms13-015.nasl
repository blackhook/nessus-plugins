#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64576);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/15");

  script_cve_id("CVE-2013-0073");
  script_bugtraq_id(57847);
  script_xref(name:"MSFT", value:"MS13-015");
  script_xref(name:"MSKB", value:"2789642");
  script_xref(name:"MSKB", value:"2789643");
  script_xref(name:"MSKB", value:"2789644");
  script_xref(name:"MSKB", value:"2789645");
  script_xref(name:"MSKB", value:"2789646");
  script_xref(name:"MSKB", value:"2789648");
  script_xref(name:"MSKB", value:"2789649");
  script_xref(name:"MSKB", value:"2789650");
  script_xref(name:"IAVA", value:"2013-A-0040-S");

  script_name(english:"MS13-015: Vulnerability in .NET Framework Could Allow Elevation of Privilege (2800277)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The version of the .NET Framework installed on the remote host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of the Microsoft .NET
Framework that is affected by a privilege escalation vulnerability due
to a flaw in the way .NET elevates the permissions of a callback
function when a particular Windows Forms object is created.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2013/ms13-015
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?bf9aafbd");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for the .NET Framework on
Windows XP, 2003, Vista, 2008, 7, 2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-0073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS13-015';
kbs = make_list(
  '2789642',
  '2789643',
  '2789644',
  '2789645',
  '2789646',
  '2789648',
  '2789649',
  '2789650'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

########## KB2789642 ###########
#  .NET Framework 4.0          #
#  Windows XP SP3,             #
#  Windows XP SP2 x64,         #
#  Windows 2003 SP2,           #
#  Windows Vista SP2,          #
#  Windows 7,                  #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2      #
################################
missing = 0;
# Windows XP SP3
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"4.0.30319.1002", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"4.0.30319.2003", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows XP SP2 x64 / Server 2003 SP2
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.1002", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.2003", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.1002", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.2003", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 / 2008 R2
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Windows.Forms.dll", version:"4.0.30319.1002", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", file:"System.Windows.Forms.dll", version:"4.0.30319.2003", min_version:"4.0.30319.1200", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789642");
vuln += missing;

######### KB2789643 ###########
#  .NET Framework 2.0 SP2     #
#  Windows XP SP 3,           #
#  Server 2003 SP2            #
###############################
missing = 0;
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"2.0.50727.7015", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.1", sp:3, file:"System.Windows.Forms.dll", version:"2.0.50727.3645", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.7015", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"5.2", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.3645", min_version:"2.0.50727.3000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789643");
vuln += missing;

########## KB2789644 ###########
#  .NET Framework 3.5.1        #
#  Windows 7,                  #
#  Server 2008 R2              #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.7015", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.4986", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789644");
vuln += missing;

########## KB2789645 ###########
#  .NET Framework 3.5.1        #
#  Windows 7 SP1,              #
#  Server 2008 R2 SP1          #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"2.0.50727.7015", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"2.0.50727.5468", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789645");
vuln += missing;

########## KB2789646 ###########
#  .NET Framework 2.0 SP2      #
#  Windows Vista SP2,          #
#  Server 2008 SP2             #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.7015", min_version:"2.0.50727.5000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"2.0.50727.4236", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789646");
vuln += missing;

########## KB2789648 ###########
#  .NET Framework 4.5          #
#  Windows Vista SP2,          #
#  Server 2008 SP2,            #
#  Windows 7 SP1,              #
#  Windows 2008 R2 SP1         #
################################
missing = 0;
# Windows Vista SP2 / Server 2008 SP2
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.18036", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.0", sp:2, file:"System.Windows.Forms.dll", version:"4.0.30319.19052", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");
# Windows 7 SP1 / 2008 R2 SP1
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"4.0.30319.18036", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.Windows.Forms.dll", version:"4.0.30319.19052", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789648");
vuln += missing;

########## KB2789649 ###########
#  .NET Framework 4.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"4.0.30319.18037", min_version:"4.0.30319.17900", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"4.0.30319.19053", min_version:"4.0.30319.19000", dir:"\Microsoft.NET\Framework\v4.0.30319");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789649");
vuln += missing;

########## KB2789650 ###########
#  .NET Framework 3.5          #
#  Windows 8,                  #
#  Server 2012                 #
################################
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.6402", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"System.Windows.Forms.dll", version:"2.0.50727.7015", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");

if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2789650");
vuln += missing;

if(vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
