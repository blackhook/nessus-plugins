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
  script_id(110500);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/24");

  script_cve_id("CVE-2018-8245");
  script_xref(name:"MSKB", value:"4011186");
  script_xref(name:"MSFT", value:"MS18-4011186");
  script_xref(name:"IAVA", value:"2018-A-0191-S");

  script_name(english:"Security Updates for Microsoft Publisher Products (June 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Publisher Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Publisher Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

- An elevation of privilege vulnerability exists when
Microsoft Publisher fails to utilize features that lock
down the Local Machine zone when instantiating OLE
objects. An attacker who successfully exploited the
vulnerability could force arbitrary code to be executed
in the Local Machine zone.  (CVE-2018-8245)");
  # https://support.microsoft.com/en-us/help/4011186/description-of-the-security-update-for-publisher-2010-june-12-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21387e8c");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4011186 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8245");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
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

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS18-06';
kbs = make_list("4011186");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

registry_init();

vuln = FALSE;

######################################################################
# Publisher Checks
######################################################################
checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7210.5000", "kb", "4011186")
);
if (hotfix_check_office_product(product:"Publisher", checks:checks, bulletin:bulletin))
  vuln = TRUE;

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
