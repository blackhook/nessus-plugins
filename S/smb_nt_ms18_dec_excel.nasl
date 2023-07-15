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
  script_id(119592);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/06/10");

  script_cve_id(
    "CVE-2018-8597",
    "CVE-2018-8598",
    "CVE-2018-8627",
    "CVE-2018-8636"
  );
  script_xref(name:"MSKB", value:"4461577");
  script_xref(name:"MSKB", value:"4461559");
  script_xref(name:"MSKB", value:"4461542");
  script_xref(name:"MSFT", value:"MS18-4461577");
  script_xref(name:"MSFT", value:"MS18-4461559");
  script_xref(name:"MSFT", value:"MS18-4461542");

  script_name(english:"Security Updates for Microsoft Excel Products (December 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - An information disclosure vulnerability exists when
    Microsoft Excel software reads out of bound memory due
    to an uninitialized variable, which could disclose the
    contents of memory. An attacker who successfully
    exploited the vulnerability could view out of bound
    memory. Exploitation of the vulnerability requires that
    a user open a specially crafted file with an affected
    version of Microsoft Excel software. The security update
    addresses the vulnerability by properly initializing the
    affected variable. (CVE-2018-8627)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2018-8597, CVE-2018-8636)

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could use the information to compromise the users
    computer or data.  (CVE-2018-8598)");
  # https://support.microsoft.com/en-us/help/4461577/descriptionofthesecurityupdateforexcel2010december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4da77a07");
  # https://support.microsoft.com/en-us/help/4461559/descriptionofthesecurityupdateforexcel2013december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1a46fea2");
  # https://support.microsoft.com/en-us/help/4461542/descriptionofthesecurityupdateforexcel2016december112018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7581dff");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461577
  -KB4461559
  -KB4461542");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8636");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
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
'4461577',
'4461559',
'4461542'
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7225.5000", "kb", "4461577"),
  "15.0", make_array("sp", 1, "version", "15.0.5093.1000", "kb", "4461559"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4783.1000", "channel", "MSI", "kb", "4461542")
  )
);

if (hotfix_check_office_product(product:"Excel", checks:checks, bulletin:bulletin))
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
