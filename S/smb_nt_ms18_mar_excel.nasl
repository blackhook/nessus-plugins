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
  script_id(108293);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2018-0907");
  script_bugtraq_id(103325);
  script_xref(name:"MSKB", value:"4011675");
  script_xref(name:"MSKB", value:"4011714");
  script_xref(name:"MSKB", value:"4011727");
  script_xref(name:"MSKB", value:"4018291");
  script_xref(name:"MSFT", value:"MS18-4011675");
  script_xref(name:"MSFT", value:"MS18-4011714");
  script_xref(name:"MSFT", value:"MS18-4011727");
  script_xref(name:"MSFT", value:"MS18-4018291");
  script_xref(name:"IAVA", value:"2018-A-0077-S");

  script_name(english:"Security Updates for Microsoft Excel Products (March 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by a security feature
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing a security update.
It is, therefore, affected by the following vulnerability :

  - A security feature bypass vulnerability exists in Microsoft
    Office software by not enforcing macro settings on an Excel
    document. The security feature bypass by itself does not allow
    arbitrary code execution. To successfully exploit the
    vulnerability, an attacker would have to embed a control in an
    Excel worksheet that specifies a macro should be run. To exploit
    the vulnerability, an attacker would have to convince a user to
    open a specially crafted file with an affected version of
    Microsoft Office software. The security update addresses the
    vulnerability by enforcing macro settings on Excel documents.
    (CVE-2018-0907)");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2018-0907
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5bf879e0");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4011675
  -KB4011714
  -KB4011727
  -KB4018291");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0907");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
include("misc_func.inc");
include("install_func.inc");

global_var vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS18-03";
kbs = make_list(
  '4011675', # Excel 2010 SP2
  '4011714', # Excel 2007 SP3
  '4011727', # Excel 2016
  '4018291'  # Excel 2013 SP1
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel 2007, 2010, 2013, 2016
######################################################################
kb16 = "4011727";
excel_checks = make_array(
  "12.0", make_array("sp", 3, "version", "12.0.6786.5000", "kb", "4011714"),
  "14.0", make_array("sp", 2, "version", "14.0.7195.5000", "kb", "4011675"),
  "15.0", make_array("sp", 1, "version", "15.0.5015.1000", "kb", "4018291"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.8201.2265", "channel", "Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.8431.2236", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
    make_array("sp", 0, "version", "16.0.9126.2072", "channel", "First Release for Deferred", "kb", kb16),
    make_array("sp", 0, "version", "16.0.9029.2253", "channel", "Current", "kb", kb16)
  )
);
if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
  vuln = TRUE;

if (vuln)
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
