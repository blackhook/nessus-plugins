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
  script_id(119599);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id("CVE-2018-8628");
  script_xref(name:"MSKB", value:"4461532");
  script_xref(name:"MSKB", value:"4461481");
  script_xref(name:"MSKB", value:"4461521");
  script_xref(name:"MSFT", value:"MS18-4461532");
  script_xref(name:"MSFT", value:"MS18-4461481");
  script_xref(name:"MSFT", value:"MS18-4461521");

  script_name(english:"Security Updates for Microsoft PowerPoint Products (December 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft PowerPoint Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft PowerPoint Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft PowerPoint software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8628)");
  # https://support.microsoft.com/en-us/help/4461532/descriptionofthesecurityupdateforpowerpoint2016december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b17533f5");
  # https://support.microsoft.com/en-us/help/4461481/descriptionofthesecurityupdateforpowerpoint2013december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5d7c9df6");
  # https://support.microsoft.com/en-us/help/4461521/descriptionofthesecurityupdateforpowerpoint2010december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40560634");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461532
  -KB4461481
  -KB4461521");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8628");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = "MS18-12";
kbs = make_list(
'4461532',
'4461481',
'4461521'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7225.5000", "kb", "4461521"),
  "15.0", make_array("sp", 1, "version", "15.0.5093.1000", "kb", "4461481"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4783.1000", "channel", "MSI", "kb", "4461532")
  )
);

if (hotfix_check_office_product(product:"PowerPoint", checks:checks, bulletin:bulletin))
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
