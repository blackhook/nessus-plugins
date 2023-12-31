#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42437);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/08/05");

  script_cve_id("CVE-2009-2512");
  script_bugtraq_id(36919);
  script_xref(name:"IAVA", value:"2009-A-0115-S");
  script_xref(name:"MSFT", value:"MS09-063");
  script_xref(name:"MSKB", value:"973565");

  script_name(english:"MS09-063: Vulnerability in Web Services on Devices API Could Allow Remote Code Execution (973565)");
  script_summary(english:"Checks version of wsdapi.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through the Web
Services for Devices API (WSDAPI)."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is running a vulnerable version of WSDAPI.
Sending the affected service a packet with a specially crafted header
can result in arbitrary code execution.  An attacker on the same subnet
could exploit this to take complete control of the system."
  );
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2009/ms09-063
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?29722a00");
  script_set_attribute(
    attribute:"solution",
    value:"Microsoft has released a set of patches for Windows Vista and 2008."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-2512");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-063';
kb = '973565';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista SP0 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6000.16903",   min_version:"6.0.6000.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6000.21103",   min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8 SP1 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6001.18306",   min_version:"6.0.6001.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6001.22491",   min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / 2k8 SP2 (x86 & x64)
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6002.18085",   min_version:"6.0.6002.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",   file:"wsdapi.dll", version:"6.0.6002.22194",   min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
