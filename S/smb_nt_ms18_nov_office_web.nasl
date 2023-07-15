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
  script_id(118927);
  script_version("1.7");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8539", "CVE-2018-8577");
  script_bugtraq_id(105834, 105835);
  script_xref(name:"MSKB", value:"4461527");
  script_xref(name:"MSKB", value:"4092473");
  script_xref(name:"MSFT", value:"MS18-4461527");
  script_xref(name:"MSFT", value:"MS18-4092473");

  script_name(english:"Security Updates for Microsoft Office Web Apps (November 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Web Apps installation on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Web Apps installation on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8577)

  - A remote code execution vulnerability exists in
    Microsoft Word software when it fails to properly handle
    objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2018-8539)");
  # https://support.microsoft.com/en-us/help/4461527/description-of-the-security-update-for-sharepoint-server-2010-office
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2bdb341b");
  # https://support.microsoft.com/en-us/help/4092473/description-of-the-security-update-for-office-web-apps-server-2013
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?77517267");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461527
  -KB4092473");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8577");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-11";
kbs = make_list(
  "4461527",
  "4092473"
);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

# Get installs of Office Web Apps
owa_installs = get_installs(app_name:"Microsoft Office Web Apps");

if (!empty_or_null(owa_installs))
{
  foreach owa_install (owa_installs[1])
  {
    if (owa_install["Product"] == "2010")
    {
      owa_2010_path = owa_install['path'];
      owa_2010_sp = owa_install['SP'];
    }
    else if (owa_install["Product"] == "2013")
    {
      owa_2013_path = owa_install["path"];
      owa_2013_sp = owa_install["SP"];
    }
  }
}
vuln = FALSE;

####################################################################
# Office Web Apps 2010 SP2
####################################################################
if (owa_2010_path && (!isnull(owa_2010_sp) && owa_2010_sp == "2"))
{
  path = hotfix_append_path(path:owa_2010_path, value:"14.0\WebServices\ConversionService\Bin\Converter");
  if (hotfix_check_fversion(file:"msoserver.dll", version:"14.0.7224.5000", min_version:"14.0.0.0", path:path, kb:"4461527", product:"Office Web Apps 2010") == HCF_OLDER)
    vuln = TRUE;
}

####################################################################
# Office Web Apps 2013 SP1
####################################################################
if (owa_2013_path && (!isnull(owa_2013_sp) && owa_2013_sp == "1"))
{
  path = hotfix_append_path(path:owa_2013_path, value:"WordConversionService\bin\Converter");
  if (hotfix_check_fversion(file:"msoserver.dll", version:"15.0.5085.1000", min_version:"15.0.0.0", path:path, kb:"4092473", product:"Office Web Apps 2013") == HCF_OLDER)
    vuln = TRUE;
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

