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
  script_id(103135);
  script_version("1.12");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id(
    "CVE-2017-8631",
    "CVE-2017-8676",
    "CVE-2017-8682",
    "CVE-2017-8695",
    "CVE-2017-8696",
    "CVE-2017-8742"
  );
  script_bugtraq_id(
    100741,
    100751,
    100755,
    100772,
    100773,
    100780
  );
  script_xref(name:"MSKB", value:"3128030");
  script_xref(name:"MSKB", value:"4011065");
  script_xref(name:"MSKB", value:"4011125");
  script_xref(name:"MSKB", value:"4011134");
  script_xref(name:"MSFT", value:"MS17-3128030");
  script_xref(name:"MSFT", value:"MS17-4011065");
  script_xref(name:"MSFT", value:"MS17-4011125");
  script_xref(name:"MSFT", value:"MS17-4011134");
  script_xref(name:"IAVA", value:"2017-A-0274");

  script_name(english:"Security Updates for Microsoft Office Viewers (September 2017)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in
    Microsoft Office software when it fails to properly
    handle objects in memory. An attacker who successfully
    exploited the vulnerability could use a specially
    crafted file to perform actions in the security context
    of the current user. For example, the file could then
    take actions on behalf of the logged-on user with the
    same permissions as the current user. Exploitation of
    this vulnerability requires that a user open a specially
    crafted file with an affected version of Microsoft
    Office software. In an email attack scenario, an
    attacker could exploit the vulnerability by sending the
    specially crafted file to the user and convincing the
    user to open the file. In a web-based attack scenario,
    an attacker could host a website (or leverage a
    compromised website that accepts or hosts user-provided
    content) that contains a specially crafted file that is
    designed to exploit the vulnerability. However, an
    attacker would have no way to force the user to visit
    the website. Instead, an attacker would have to convince
    the user to click a link, typically by way of an
    enticement in an email or Instant Messenger message, and
    then convince the user to open the specially crafted
    file. The security update addresses the vulnerability by
    correcting how Microsoft Office handles files in memory.
    (CVE-2017-8631)

  - A remote code execution vulnerability exists when the
    Windows font library improperly handles specially
    crafted embedded fonts. An attacker who successfully
    exploited this vulnerability could take control of the
    affected system. An attacker could then install
    programs; view, change, or delete data; or create new
    accounts with full user rights. Users whose accounts are
    configured to have fewer user rights on the system could
    be less impacted than users who operate with
    administrative user rights. There are multiple ways an
    attacker could exploit this vulnerability. In a web-
    based attack scenario, an attacker could host a
    specially crafted website that is designed to exploit
    this vulnerability and then convince a user to view the
    website. An attacker would have no way to force users to
    view the attacker-controlled content. Instead, an
    attacker would have to convince users to take action,
    typically by getting them to click a link in an email
    message or in an Instant Messenger message that takes
    users to the attacker's website, or by opening an
    attachment sent through email. In a file sharing attack
    scenario, an attacker could provide a specially crafted
    document file that is designed to exploit this
    vulnerability, and then convince a user to open the
    document file. The security update addresses the
    vulnerabilities by correcting how the Windows font
    library handles embedded fonts. (CVE-2017-8682)

  - An information disclosure vulnerability exists when
    Windows Uniscribe improperly discloses the contents of
    its memory. An attacker who successfully exploited the
    vulnerability could obtain information to further
    compromise the users system. There are multiple ways an
    attacker could exploit the vulnerability, such as by
    convincing a user to open a specially crafted document
    or by convincing a user to visit an untrusted webpage.
    The update addresses the vulnerability by correcting how
    Windows Uniscribe handles objects in memory.
    (CVE-2017-8695)

  - A remote code execution vulnerability exists due to the
    way Windows Uniscribe handles objects in memory. An
    attacker who successfully exploited this vulnerability
    could take control of the affected system. An attacker
    could then install programs; view, change, or delete
    data; or create new accounts with full user rights.
    Users whose accounts are configured to have fewer user
    rights on the system could be less impacted than users
    who operate with administrative user rights. There are
    multiple ways an attacker could exploit this
    vulnerability: In a web-based attack scenario, an
    attacker could host a specially crafted website designed
    to exploit this vulnerability and then convince a user
    to view the website. An attacker would have no way to
    force users to view the attacker-controlled content.
    Instead, an attacker would have to convince users to
    take action, typically by getting them to click a link
    in an email or instant message that takes users to the
    attacker's website, or by opening an attachment sent
    through email. In a file-sharing attack scenario, an
    attacker could provide a specially crafted document file
    designed to exploit this vulnerability and then convince
    a user to open the document file.The security update
    addresses the vulnerability by correcting how Windows
    Uniscribe handles objects in memory. (CVE-2017-8696)

  - A remote code execution vulnerability exists in
    Microsoft Office software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights. Users whose accounts are configured to have
    fewer user rights on the system could be less impacted
    than users who operate with administrative user rights.
    Exploitation of the vulnerability requires that a user
    open a specially crafted file with an affected version
    of Microsoft Office software. In an email attack
    scenario, an attacker could exploit the vulnerability by
    sending the specially crafted file to the user and
    convincing the user to open the file. In a web-based
    attack scenario, an attacker could host a website (or
    leverage a compromised website that accepts or hosts
    user-provided content) that contains a specially crafted
    file designed to exploit the vulnerability. An attacker
    would have no way to force users to visit the website.
    Instead, an attacker would have to convince users to
    click a link, typically by way of an enticement in an
    email or instant message, and then convince them to open
    the specially crafted file. Note that the Preview Pane
    is not an attack vector for this vulnerability. The
    security update addresses the vulnerability by
    correcting how Office handles objects in memory.
    (CVE-2017-8742)

  - An information disclosure vulnerability exists in the
    way that the Windows Graphics Device Interface (GDI)
    handles objects in memory, allowing an attacker to
    retrieve information from a targeted system. By itself,
    the information disclosure does not allow arbitrary code
    execution; however, it could allow arbitrary code to be
    run if the attacker uses it in combination with another
    vulnerability. To exploit this vulnerability, an
    attacker would have to log on to an affected system and
    run a specially crafted application. Note that where the
    severity is indicated as Critical in the Affected
    Products table, the Preview Pane is an attack vector for
    this vulnerability. The security update addresses the
    vulnerability by correcting how GDI handles memory
    addresses. (CVE-2017-8676)");
  # https://support.microsoft.com/en-us/help/3128030/descriptionofthesecurityupdateforpowerpointviewerseptember12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60ba21b6");
  # https://support.microsoft.com/en-us/help/4011065/descriptionofthesecurityupdateforexcelviewer2007september12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60960496");
  # https://support.microsoft.com/en-us/help/4011125/descriptionofthesecurityupdateforwordviewerseptember12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a90e90a1");
  # https://support.microsoft.com/en-us/help/4011134/descriptionofthesecurityupdateforwordviewerseptember12-2017
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d857f2e2");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB3128030
  -KB4011065
  -KB4011125
  -KB4011134");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-8742");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = "MS17-09";
kbs = make_list(
  '3128030', # PowerPoint Viewer 2007
  '4011065', # Excel Viewer 2007 SP3
  '4011125', # Office Word Viewer
  '4011134'  # Office Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

vuln = FALSE;
port = kb_smb_transport();

######################################################################
# Excel Viewer
######################################################################
function perform_excel_viewer_checks()
{
  var excel_vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6776.5000", "kb", "4011065")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# PowerPoint Viewer
######################################################################
function perform_powerpoint_viewer_checks()
{
  var ppt_vwr_checks = make_array(
    "14.0", make_array("version", "14.0.7188.5000", "kb", "3128030")
  );
  if (hotfix_check_office_product(product:"PowerPointViewer", display_name:"PowerPoint Viewer", checks:ppt_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# Word Viewer
######################################################################
function perform_word_viewer_checks()
{
  var install, installs, path;

  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(isnull(installs)) return NULL;

  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"gdiplus.dll", version:"11.0.8443.0", kb:"4011134", product:"Microsoft Word Viewer") == HCF_OLDER)
      vuln = TRUE;
  }

  path = hotfix_get_officecommonfilesdir(officever:"11.0");
  path = hotfix_append_path(path:path, value:"Microsoft Shared\Office11");
  if(hotfix_check_fversion(path:path, file:"usp10.dll", version:"1.626.6002.24173", kb:"4011125", product:"Microsoft Word Viewer") == HCF_OLDER)
    vuln = TRUE;
}

######################################################################
# MAIN
######################################################################
perform_excel_viewer_checks();
perform_powerpoint_viewer_checks();
perform_word_viewer_checks();

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
