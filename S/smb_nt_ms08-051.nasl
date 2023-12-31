#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33880);
 script_version("1.30");
 script_cvs_date("Date: 2018/11/15 20:50:30");

 script_cve_id("CVE-2008-0120", "CVE-2008-0121", "CVE-2008-1455");
 script_bugtraq_id(30552, 30554, 30579);

 script_xref(name:"MSFT", value:"MS08-051");
 script_xref(name:"MSKB", value:"948988");
 script_xref(name:"MSKB", value:"948995");
 script_xref(name:"MSKB", value:"949007");
 script_xref(name:"MSKB", value:"949041");
 script_xref(name:"MSKB", value:"951338");

 script_name(english:"MS08-051: Vulnerabilities in Microsoft PowerPoint Could Allow Remote Code Execution (949785)");
 script_summary(english:"Determines the version of PowerPoint.exe");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
PowerPoint.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft PowerPoint which is
subject to a flaw that could allow arbitrary code to be run.

An attacker may use this to execute arbitrary code on this host.

To succeed, the attacker would have to send a rogue file to a user of
the remote computer and have it open it.  Then a bug in the font parsing
handler would result in code execution.");
 script_set_attribute(attribute:"see_also", value:"https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2008/ms08-051");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for PowerPoint 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_cwe_id(399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2018 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');

 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-051';
kbs = make_list("948988", "948995", "949007", "949041", "951338");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);
port = get_kb_item("SMB/transport");

#
# PowerPoint
#
list = get_kb_list("SMB/Office/PowerPoint/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/PowerPoint/' - '/ProductPath';
    if(ereg(pattern:"^9\..*", string:v))
    {
      # PowerPoint 2000 - fixed in 9.0.0.8969
      office_sp = get_kb_item("SMB/Office/2000/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        sub =  ereg_replace(pattern:"^9\.00?\.00?\.([0-9]*)$", string:v, replace:"\1");
        if(sub != v && int(sub) < 8969 ) {
          vuln++;
          kb = '949007';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^10\..*", string:v))
    {
      # PowerPoint XP - fixed in 10.0.6842.0
      office_sp = get_kb_item("SMB/Office/XP/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        middle =  ereg_replace(pattern:"^10\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6842) {
          vuln++;
          kb = '948995';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^11\..*", string:v))
    {
      # PowerPoint 2003 - fixed in 11.0.8227.0
      office_sp = get_kb_item("SMB/Office/2003/SP");
      if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
      {
        middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 8227 ) {
          vuln++;
          kb = '948988';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
    else if(ereg(pattern:"^12\..*", string:v))
    {
      # PowerPoint 2007 - fixed in 12.0.6300.5000
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && (office_sp == 0 || office_sp == 1))
      {
        middle =  ereg_replace(pattern:"^12\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
        if(middle != v && int(middle) < 6300 ) {
          vuln++;
          kb = '951338';
          hotfix_add_report(bulletin:bulletin, kb:kb);
        }
      }
    }
  }
}

list = get_kb_list("SMB/Office/PowerPointViewer/*/ProductPath");
if (!isnull(list))
{
  foreach item (keys(list))
  {
    v = item - 'SMB/Office/PowerPointViewer/' - '/ProductPath';
    if(ereg(pattern:"^11\..*", string:v))
    {
      # PowerPointViewer 2003 - fixed in 11.0.8164.0
      middle =  ereg_replace(pattern:"^11\.0\.([0-9]*)\.[0-9]*$", string:v, replace:"\1");
      if(middle != v && int(middle) < 8164 ) {
        kb = '949041';
        hotfix_add_report(bulletin:bulletin, kb:kb);
      }
    }
  }
}
if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
