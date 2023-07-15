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
  script_id(147228);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2021-26411");
  script_xref(name:"MSKB", value:"5000847");
  script_xref(name:"MSKB", value:"5000800");
  script_xref(name:"MSKB", value:"5000841");
  script_xref(name:"MSKB", value:"5000844");
  script_xref(name:"MSKB", value:"5000848");
  script_xref(name:"MSFT", value:"MS21-5000847");
  script_xref(name:"MSFT", value:"MS21-5000800");
  script_xref(name:"MSFT", value:"MS21-5000841");
  script_xref(name:"MSFT", value:"MS21-5000844");
  script_xref(name:"MSFT", value:"MS21-5000848");
  script_xref(name:"IAVA", value:"2021-A-0130-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0015");

  script_name(english:"Security Updates for Internet Explorer (March 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The Internet Explorer installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Internet Explorer installation on the remote host is
missing a security update. It is, therefore, affected by the
following vulnerability:

  - A memory corruption vulnerability exists. An attacker
    can exploit this to corrupt the memory and cause
    unexpected behaviors within the system/application.
    (CVE-2021-26411)");
  # https://support.microsoft.com/en-us/topic/kb5000800-cumulative-security-update-for-internet-explorer-march-9-2021-b7b43be0-e9ef-48b6-b102-ed28fd89e0f2
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8426b33");
  # https://support.microsoft.com/en-us/topic/march-9-2021-kb5000841-monthly-rollup-3a2cced1-f436-40c3-a8a1-645f86759088
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8c5851d4");
  # https://support.microsoft.com/en-us/topic/march-9-2021-kb5000844-monthly-rollup-d90d0eb1-6319-4a7e-97f6-68fbd306fd5a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?177a5bc6");
  # https://support.microsoft.com/en-us/topic/march-9-2021-kb5000847-monthly-rollup-8afa2933-e9da-4481-a0bc-18deb314974e
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df958afd");
  # https://support.microsoft.com/en-us/topic/march-9-2021-kb5000848-monthly-rollup-52f23db9-e1b0-4829-81b9-198fc82891a3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ff1e9b3");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5000800
  -KB5000841
  -KB5000844
  -KB5000847
  -KB5000848");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-26411");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_check_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS21-03';
kbs = make_list(
  '5000800',
  '5000841',
  '5000844',
  '5000847',
  '5000848'
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
 audit(AUDIT_OS_SP_NOT_VULN);
if ("Vista" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.19963", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5000800") ||

  # Windows Server 2012
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"11.0.9600.19963", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5000800") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.19963", min_version:"11.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"5000800") ||

  # Windows Server 2008
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.21532", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"5000800")
)
{
  report =  '\nNote: The fix for this issue is available in either of the following updates:\n';
  report += '  - KB5000800 : Cumulative Security Update for Internet Explorer\n';

  if(os == "6.3")
  {
    report += '  - KB5000848 : Windows 8.1 / Server 2012 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS21-03', kb:'5000848', report);
  }
  else if(os == "6.2")
  {
    report += '  - KB5000847 : Windows Server 2012 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS21-03', kb:'5000847', report);
  }
  else if(os == "6.1")
  {
    report += '  - KB5000841 : Windows 7 / Server 2008 R2 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS21-03', kb:'5000841', report);
  }
  else if(os == "6.0")
  {
    report += '  - KB5000844 : Windows Server 2008 Monthly Rollup\n';
    hotfix_add_report(bulletin:'MS21-03', kb:'5000844', report);
  }

  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);

  port = kb_smb_transport();

  hotfix_security_warning();
  hotfix_check_fversion_end();
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, hotfix_get_audit_report());
}

