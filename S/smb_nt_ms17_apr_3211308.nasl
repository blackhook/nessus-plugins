#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(107195);
  script_version("1.5");
  script_cvs_date("Date: 2018/09/10 11:37:06");

  script_cve_id("CVE-2017-0163", "CVE-2017-0168","CVE-2017-0180");
  script_bugtraq_id(97418, 97444, 97465);
  script_xref(name:"MSKB", value:"3211308");
  script_xref(name:"MSFT", value:"MS17-3211308");

  script_name(english:"KB3211308: Security Update for Hyper-V in Windows Server 2008 (April 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update KB3211308. It is,
therefore, affected by multiple vulnerabilities:

  - Multiple flaws exist in Windows Hyper-V Network Switch
    due to improper validation of input from the guest
    operating system. A local attacker can exploit these,
    via a specially crafted application on the guest, to
    execute arbitrary code on the host system.
    (CVE-2017-0163, CVE-2017-0180)

  - Multiple information disclosure vulnerabilities exist in
    Windows Hyper-V Network Switch due to improper
    validation of user-supplied input. A guest attacker can
    exploit these to disclose sensitive information on the
    host server. (CVE-2017-0168)");
  # https://support.microsoft.com/en-us/help/3211308/security-update-for-hyper-v-in-windows-server-2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?af1cd2f2");
  script_set_attribute(attribute:"solution", value:
"Apply security update KB3211308.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/07");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018 Tenable Network Security, Inc.");

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
kbs = make_list('3211308');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
    # Windows Server 2008
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"vmswitch.sys", version:"6.0.6002.19748", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3211308") ||
    hotfix_is_vulnerable(os:"6.0", sp:2, file:"vmswitch.sys", version:"6.0.6002.24071", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"3211308")
  )
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
