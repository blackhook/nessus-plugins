#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105700);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2018-0792",
    "CVE-2018-0793",
    "CVE-2018-0794",
    "CVE-2018-0797",
    "CVE-2018-0798",
    "CVE-2018-0845",
    "CVE-2018-0848",
    "CVE-2018-0849",
    "CVE-2018-0862"
  );
  script_bugtraq_id(
    102370,
    102373,
    102375,
    102381,
    102406
  );
  script_xref(name:"MSKB", value:"4011657");
  script_xref(name:"MSKB", value:"4011643");
  script_xref(name:"MSKB", value:"4011659");
  script_xref(name:"MSKB", value:"4011651");
  script_xref(name:"MSFT", value:"MS18-4011657");
  script_xref(name:"MSFT", value:"MS18-4011643");
  script_xref(name:"MSFT", value:"MS18-4011659");
  script_xref(name:"MSFT", value:"MS18-4011651");
  script_xref(name:"IAVA", value:"2018-A-0009-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");

  script_name(english:"Security Updates for Microsoft Word Products (January 2018)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Words Products are missing security updates. It is
therefore affected by multiple issues involving handling of Office
and RTF (Rich Text Format) files. If successfully exploited, an
attacker could execute code in the context of the current user.");
  # https://support.microsoft.com/en-us/help/4011657/description-of-the-security-update-for-word-2007-january-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b1d0d8a");
  # https://support.microsoft.com/en-us/help/4011659/description-of-the-security-update-for-word-2010-january-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?65eb88a5");
  # https://support.microsoft.com/en-us/help/4011651/descriptionofthesecurityupdateforword2013january9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ceece7f");
  # https://support.microsoft.com/en-us/help/4011643/description-of-the-security-update-for-word-2016-january-9-2018
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3a6c85db");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:
  -KB4011657
  -KB4011659
  -KB4011651
  -KB4011643");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0862");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

bulletin = "MS18-01";
kbs = make_list(
  '4011657', # Word 2007 SP3
  '4011659', # Word 2010 SP2
  '4011651', # Word 2013 SP1
  '4011643'  # Word 2016
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Word 2007, 2010, 2013, 2016
######################################################################
function perform_word_checks()
{
  local_var word_checks, kb16;

  kb16 = "4011643";
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6784.5000", "kb", "4011657"),
    "14.0", make_array("sp", 2, "version", "14.0.7192.5000", "kb", "4011659"),
    "15.0", make_array("sp", 1, "version", "15.0.4997.1000", "kb", "4011651"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4639.1000", "channel", "MSI", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2153", "channel", "Deferred", "channel_version", "1708", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8201.2217", "channel", "Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8431.2153", "channel", "First Release for Deferred", "kb", kb16),
      make_array("sp", 0, "version", "16.0.8730.2175", "channel", "Current", "kb", kb16)
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# MAIN
######################################################################
perform_word_checks();

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
