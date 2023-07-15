#
# (C) Tenable Network Security, Inc.
#


# The descriptive text and package checks in this plugin were
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(135462);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/17");

  script_cve_id("CVE-2020-0760");
  script_xref(name:"MSKB", value:"3162033");
  script_xref(name:"MSKB", value:"4011097");
  script_xref(name:"MSKB", value:"4032216");
  script_xref(name:"MSFT", value:"MS20-3162033");
  script_xref(name:"MSFT", value:"MS20-4011097");
  script_xref(name:"MSFT", value:"MS20-4032216");
  script_xref(name:"IAVA", value:"2020-A-0173-S");

  script_name(english:"Security Updates for Microsoft Publisher Products (April 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Publisher Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Publisher Products are missing a security
update. It is, therefore, affected by the following
vulnerability :

  - A remote code execution vulnerability exists when
    Microsoft Office improperly loads arbitrary type
    libraries. An attacker could then install programs;
    view, change, or delete data; or create new accounts
    with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could
    be less impacted than users who operate with
    administrative user rights.  (CVE-2020-0760)");
  # https://support.microsoft.com/en-us/help/4032216/security-update-for-publisher-2010-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85039829");
  # https://support.microsoft.com/en-us/help/4011097/security-update-for-publisher-2016-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c76ab85c");
  # https://support.microsoft.com/en-us/help/3162033/security-update-for-publisher-2013-april-14-2020
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de36ff44");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB3162033
  -KB4011097
  -KB4032216");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-0760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:publisher");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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


get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS20-04';
kbs = make_list(
  "3162033",
  "4011097",
  "4032216"
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

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
  # 2010
  "14.0", make_array("sp", 2, "version", "14.0.7248.5000", "kb", "4032216"),
  # 2013
  "15.0", make_array("sp", 1, "version", "15.0.5233.1000", "kb", "3162033"),
  # 2016
  '16.0', make_nested_list(
    make_array('sp', 0, 'version', '16.0.4993.1001', 'channel', 'MSI', 'kb', '4011097'),
    # C2R
    make_array('version', '16.0.11328.20564', 'channel', 'Deferred'),
    make_array('version', '16.0.11929.20708', 'channel', 'Deferred', 'channel_version', '1908'),
    make_array('version', '16.0.12527.20442', 'channel', 'First Release for Deferred'),
    make_array('version', '16.0.12624.20442', 'channel', 'Current'),
    # 2019
    make_array('version', '16.0.12624.20442', 'channel', '2019 Retail'),
    make_array('version', '16.0.10358.20061', 'channel', '2019 Volume')
    )
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
