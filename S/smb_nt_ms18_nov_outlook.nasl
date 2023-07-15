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
  script_id(118928);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2018-8522",
    "CVE-2018-8524",
    "CVE-2018-8558",
    "CVE-2018-8576",
    "CVE-2018-8579",
    "CVE-2018-8582"
  );
  script_bugtraq_id(
    105820,
    105822,
    105823,
    105825,
    105826,
    105828
  );
  script_xref(name:"MSKB", value:"4461486");
  script_xref(name:"MSKB", value:"4461529");
  script_xref(name:"MSKB", value:"4461506");
  script_xref(name:"MSFT", value:"MS18-4461486");
  script_xref(name:"MSFT", value:"MS18-4461529");
  script_xref(name:"MSFT", value:"MS18-4461506");

  script_name(english:"Security Updates for Outlook (November 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote
host is missing security updates. It is, therefore, affected
by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft Outlook parses specially modified rule
    export files. An attacker who successfully exploited
    this vulnerability could take control of an affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8582)

  - A remote code execution vulnerability exists in
    Microsoft Outlook software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2018-8522,
    CVE-2018-8524, CVE-2018-8576)");
  # https://support.microsoft.com/en-us/help/4461486/description-of-the-security-update-for-outlook-2013-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2f1e130");
  # https://support.microsoft.com/en-us/help/4461529/description-of-the-security-update-for-outlook-2010-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5aacb9dd");
  # https://support.microsoft.com/en-us/help/4461506/description-of-the-security-update-for-outlook-2016-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1543bb6");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461486
  -KB4461529
  -KB4461506");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8582");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-11";
kbs = make_list(
'4461486',
'4461529',
'4461506'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("version", "14.0.7224.5000", "kb", "4461529"),
  "15.0", make_array("version", "15.0.5085.1000", "kb", "4461486"),
  "16.0", make_nested_list(
    make_array("version", "16.0.4771.1000", "channel", "MSI", "kb", "4461506")
  )
);

if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
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
