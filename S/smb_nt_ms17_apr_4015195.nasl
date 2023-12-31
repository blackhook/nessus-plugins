#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include("compat.inc");

if (description)
{
  script_id(99307);
  script_version("1.14");
  script_cvs_date("Date: 2018/11/15 20:50:32");

  script_cve_id("CVE-2017-0058","CVE-2017-0155");
  script_bugtraq_id(97462,97471);
  script_xref(name:"MSKB", value:"4015195");
  script_xref(name:"MSFT", value:"MS17-4015195");

  script_name(english:"KB4015195: Security Update for the Win32k Information Disclosure Vulnerability (April 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update KB4015195. It is,
therefore, affected by multiple vulnerabilities:

  - An information disclosure vulnerability in the win32k 
    component due to improper handling of kernel 
    information. A local attacker can exploit this, via a 
    specially crafted application,to disclose sensitive 
    information. (CVE-2017-0058)

  - An elevation of privilege vulnerability exists in 
    Windows when the Win32k component fails to properly 
    handle objects in memory. An attacker who successfully 
    exploited this vulnerability could run arbitrary code 
    in kernel mode. (CVE-2017-0155)");
  # https://support.microsoft.com/en-us/help/4015195/security-update-for-the-win32k-information-disclosure-vulnerabilities
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d1b7940e");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2017-0058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce1d6587");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB4015195.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/12");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

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

bulletin = 'MS17-04';
kbs = make_list('4015195');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
    # Vista / Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.19749", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"4015195") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"win32k.sys", version:"6.0.6002.24072", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:"4015195")
  )
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
