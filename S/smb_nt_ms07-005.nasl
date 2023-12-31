#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24329);
 script_version("1.27");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id("CVE-2006-3448");
 script_bugtraq_id(22484);
 script_xref(name:"MSFT", value:"MS07-005");
 script_xref(name:"MSKB", value:"923723");
 
 script_xref(name:"CERT", value:"466873");

 script_name(english:"MS07-005: Vulnerability in Step-by-Step Interactive Training Could Allow Remote Code Execution (923723)");
 script_summary(english:"Determines the version of MRUN32.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the training
software.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Step-by-Step
Interactive Training that contains a flaw that could lead to remote code
execution.

To exploit this flaw, an attacker would need to trick a user on the
remote host into opening a malformed file with the affected
application.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2007/ms07-005");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:step-by-step_interactive_training");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-005';
kbs = make_list("923723");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


if ( ! get_kb_item("SMB/WindowsVersion") ) exit(1);

if ( hotfix_check_fversion(file:"mrun32.exe", version:"3.4.1.102", bulletin:"MS07-005", kb:"923723") == HCF_OLDER ) {
 set_kb_item(name:"SMB/Missing/MS07-005", value:TRUE);
 hotfix_security_hole();
 }

hotfix_check_fversion_end();
