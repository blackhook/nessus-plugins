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
  script_id(118958);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/01");

  script_cve_id("CVE-2018-8575");
  script_bugtraq_id(105807);
  script_xref(name:"MSKB", value:"4461489");
  script_xref(name:"MSKB", value:"4022147");
  script_xref(name:"MSKB", value:"4461478");
  script_xref(name:"MSFT", value:"MS18-4461489");
  script_xref(name:"MSFT", value:"MS18-4022147");
  script_xref(name:"MSFT", value:"MS18-4461478");

  script_name(english:"Security Updates for Microsoft Project Server (November 2018)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Project Server installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Project Server installation on the remote host
is missing a security update. It is, therefore, affected by
the following vulnerability :

  - A remote code execution vulnerability exists in
    Microsoft Project software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user.  (CVE-2018-8575)");
  # https://support.microsoft.com/en-us/help/4461489/description-of-the-security-update-for-project-2013-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49ac1ceb");
  # https://support.microsoft.com/en-us/help/4022147/description-of-the-security-update-for-project-2010-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?03a2eb7b");
  # https://support.microsoft.com/en-us/help/4461478/description-of-the-security-update-for-project-2016-november-13-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a85cc1a4");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB4461489
  -KB4022147
  -KB4461478");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8575");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
  '4022147', # 2010
  '4461489', # 2013
  '4461478'  # 2016
);

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

port = kb_smb_transport();

######################################################################
# project 2010, 2013, 2016
######################################################################
project_checks = make_array(
  "14.0", make_array("sp", 2, "version", "14.0.7224.5000", "kb", "4022147"),
  "15.0", make_array("sp", 1, "version", "15.0.5085.1000", "kb", "4461489"),
  "16.0", make_nested_list(
    make_array("sp", 0, "version", "16.0.4771.1000", "channel", "MSI", "kb", "4461478"),
    # C2R
    make_array("sp", 0, "version", "16.0.8431.2329", "channel", "Deferred"),
    make_array("sp", 0, "version", "16.0.9126.2315", "channel", "Deferred", "channel_version", "1803"),
    make_array("sp", 0, "version", "16.0.10730.20205", "channel", "First Release for Deferred"),
    make_array("sp", 0, "version", "16.0.11001.20108", "channel", "Current"),
    # 2019
    make_array("sp", 0, "version", "16.0.11001.20108", "channel", "2019 Retail"),
    make_array("sp", 0, "version", "16.0.10338.20019", "channel", "2019 Volume")
    )
  );

if (hotfix_check_office_product(product:"Project", checks:project_checks, bulletin:bulletin))
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
