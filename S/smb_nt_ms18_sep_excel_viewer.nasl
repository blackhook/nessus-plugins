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
  script_id(117422);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8429");
  script_bugtraq_id(105219);
  script_xref(name:"MSKB", value:"4092467");
  script_xref(name:"MSFT", value:"MS18-4092467");

  script_name(english:"Security Updates for Microsoft Office Viewer Products (September 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Viewer Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Viewer Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - An information disclosure vulnerability exists when
    Microsoft Excel improperly discloses the contents of its
    memory. An attacker who exploited the vulnerability
    could access information previously deleted from the
    active worksheet.  (CVE-2018-8429)");
  # https://support.microsoft.com/en-us/help/4092467/description-of-the-security-update-for-excel-viewer-2007-september-11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c4c6ce94");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4092467 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8429");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-09";
kbs = make_list(
  '4092467' # Excel Viewer 2007 SP3
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel Viewer
######################################################################

prod_exel = "Microsoft Excel Viewer";
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");

foreach install (keys(installs))
{
  common_path = installs[install];
  path = ereg_replace(pattern:"^([A-Za-z]:.*)\\Microsoft Office.*", replace:"\1\Microsoft Office\Office12", string:common_path);

  if (hotfix_check_fversion(file:"xlview.exe", version:"12.0.6803.5000", path:path, kb:"4092467", product:prod_exel) == HCF_OLDER) vuln = TRUE;
}

if(vuln)
{
  replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
