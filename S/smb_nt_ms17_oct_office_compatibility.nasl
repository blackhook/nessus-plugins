#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103751);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/17");

  script_cve_id("CVE-2017-11826");
  script_bugtraq_id(167045);
  script_xref(name:"MSFT", value:"MS17-3213647");
  script_xref(name:"IAVA", value:"2017-A-0291-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Security Updates for Microsoft Office Compatibility Pack SP3 (October 2017)");

  script_set_attribute(attribute:"synopsis", value:
"Microsoft Office Compatibility Pack SP3 is affected by a remote
code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"Microsoft Office Compatibility Pack SP3 is missing a security update.
It is, therefore, affected by a remote code execution
vulnerability :

  - A remote code execution vulnerability exists in Microsoft Office
    software when the software fails to properly handle objects in
    memory. An attacker who successfully exploited the vulnerability
    could run arbitrary code in the context of the current user. If
    the current user is logged on with administrative user rights,
    an attacker could take control of the affected system. An
    attacker could then install programs; view, change, or delete
    data; or create new accounts with full user rights. Users whose
    accounts are configured to have fewer user rights on the system
    could be less impacted than users who operate with
    administrative user rights.

    Exploitation of the vulnerability requires that a user open a
    specially crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an attacker could
    exploit the vulnerability by sending the specially crafted file
    to the user and convincing the user to open the file. In a
    web-based attack scenario, an attacker could host a website (or
    leverage a compromised website that accepts or hosts
    user-provided content) containing a specially crafted file
    designed to exploit the vulnerability. An attacker would have no
    way to force users to visit the website. Instead, an attacker
    would have to convince users to click a link, typically by way
    of an enticement in an email or instant message, and then
    convince them to open the specially crafted file.

    The security update addresses the vulnerability by correcting
    how Office handles objects in memory. (CVE-2017-11826)");
  # https://support.microsoft.com/en-us/help/3213647/description-of-the-security-update-for-office-compatibility-pack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c16afbdf");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security update to address this issue:
  -KB3213647");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11826");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("misc_func.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS17-10";
kbs = make_list(
  '3213647'
);

vuln = FALSE;

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

####################################################################
# Office Compatibility Pack
####################################################################
installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
foreach install (keys(installs))
{
  path = installs[install];
  path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
  if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6779.5000", kb:"3213647", min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
  {
    vuln = TRUE;
    break;
  }
}

if(vuln)
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
