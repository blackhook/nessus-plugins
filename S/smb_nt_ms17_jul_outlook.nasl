#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102035);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-8571", "CVE-2017-8572", "CVE-2017-8663");
  script_bugtraq_id(99452, 99453, 100004);
  script_xref(name:"MSKB", value:"2956078");
  script_xref(name:"MSFT", value:"MS17-2956078");
  script_xref(name:"MSKB", value:"3213643");
  script_xref(name:"MSFT", value:"MS17-3213643");
  script_xref(name:"MSKB", value:"4011052");
  script_xref(name:"MSFT", value:"MS17-4011052");
  script_xref(name:"MSKB", value:"4011078");
  script_xref(name:"MSFT", value:"MS17-4011078");

  script_name(english:"Security Updates for Outlook (July 2017)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office or Outlook application installed on the remote
Windows host is missing a security update. It is, therefore, affected
by multiple vulnerabilities :

  - A security feature bypass vulnerability exists in
    Microsoft Office due to improper handling of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, by convincing a user to open and
    interact with a specially crafted document file, to
    bypass security measures and execute arbitrary commands.
    (CVE-2017-8571)

  - An information disclosure vulnerability exists in
    Microsoft Office due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    this, by convincing a user to open a specially crafted
    document file, to disclose the contents of memory.
    (CVE-2017-8572)

  - A remote code execution vulnerability exists in
    Microsoft Outlook due to improper parsing of email
    messages. An unauthenticated, remote attacker can
    exploit this, with a specially crafted email message
    with a malicious attachment, to execute arbitrary code
    in the context of the current user. (CVE-2017-8663)");
  script_set_attribute(attribute:"see_also", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/summary");
  # https://blogs.technet.microsoft.com/office_sustained_engineering/2017/07/27/new-updates-are-available-for-outlook/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a682ddf");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook 2007, 2010, 2013,
and 2016.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8663");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS17-07";
kbs = make_list(
  '2956078', # Outlook 2010 SP2
  '3213643', # Outlook 2007 SP3
  '4011052', # Outlook 2016
  '4011078'  # Outlook 2013 SP1
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Outlook 2007, 2010, 2013, 2016
######################################################################
function perform_outlook_checks()
{
  local_var checks, kb16;

  kb16 = "4011052";
  checks = make_array(
    "12.0", make_array("version", "12.0.6774.5000", "kb", "3213643"),
    "14.0", make_array("version", "14.0.7187.5000", "kb", "2956078"),
    "15.0", make_array("version", "15.0.4953.1001", "kb", "4011078"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4573.1001", "channel", "MSI", "kb", kb16),

      make_array("sp", 0, "version", "16.0.7369.2154", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.7766.2099", "channel", "Deferred", "channel_version", "1701", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2158", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8326.2058", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# MAIN
######################################################################
perform_outlook_checks();

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
