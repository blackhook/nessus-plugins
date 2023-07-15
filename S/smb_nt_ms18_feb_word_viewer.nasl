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
  script_id(106817);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0851");
  script_bugtraq_id(102870);
  script_xref(name:"MSKB", value:"4011703");
  script_xref(name:"MSFT", value:"MS18-4011703");
  script_xref(name:"IAVA", value:"2018-A-0051-S");

  script_name(english:"Security Updates for Microsoft Word Viewer (February 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Viewer application installed on the remote 
host missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Viewer application installed on the remote
host is missing a security update.
It is, therefore, affected by the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Office software when the Office software fails
    to properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-0851)");
  # https://support.microsoft.com/en-us/help/4011703/descriptionofthesecurityupdateforwordviewerfebruary13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?adbc8328");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4011703 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0851");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-02";
kbs = make_list(
  '4011703'  # Office Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();
prod = "Microsoft Word Viewer";

var install, installs, path;
installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
foreach install (keys(installs))
{
common_path = installs[install];
common_path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Common Files", string:common_path);

path = hotfix_append_path(
  path  : common_path,
  value : "Microsoft Shared\Office11"
);

if (hotfix_check_fversion(file:"mso.dll", version:"11.0.8447.0", path:path, kb:"4011703", product:prod) == HCF_OLDER)
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
