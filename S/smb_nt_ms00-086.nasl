#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10632);
 script_version("1.47");
 script_cvs_date("Date: 2018/11/15 20:50:29");

 script_cve_id("CVE-2000-0886");
 script_bugtraq_id(1912);
 script_xref(name:"MSFT", value:"MS00-086");
 script_xref(name:"MSKB", value:"277873");

 script_name(english:"MS00-086: Webserver file request parsing (277873)");
 script_summary(english:"Determines whether the hotfix Q277873 is installed");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Webserver file request parsing' problem has not
been applied.

This vulnerability can allow an attacker to execute arbitrary commands
through the remote IIS server.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2000/ms00-086");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 4.0 and 5.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/11/07");
 script_set_attribute(attribute:"patch_publication_date", value:"2000/11/06");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, "Host/patch_management_checks");

 exit(0);
}

include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS00-086';
kb = "277873";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp(nt:7, win2k:2) <= 0) exit(0, "The host is not affected based on its version / service pack.");


if (
  hotfix_missing(name:"293826") <= 0 ||
  hotfix_missing(name:"295534") <= 0 ||
  hotfix_missing(name:"301625") <= 0 ||
  hotfix_missing(name:"317636") <= 0 ||
  hotfix_missing(name:"299444") <= 0 ||
  hotfix_missing(name:"SP2SRP1") <= 0
) exit(0, "The host is not affected.");

if (hotfix_missing(name:"Q277873") > 0)
{
  if (
    defined_func("report_xml_tag") &&
    !isnull(bulletin) &&
    !isnull(kb)
  ) report_xml_tag(tag:bulletin, value:kb);

  hotfix_security_hole();
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  exit(0);
}
else exit(0, "The host is not affected.");


