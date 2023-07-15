#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177245);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/10");

  script_cve_id("CVE-2023-33131");
  script_xref(name:"MSKB", value:"5002382");
  script_xref(name:"MSKB", value:"5002387");
  script_xref(name:"MSFT", value:"MS23-5002382");
  script_xref(name:"MSFT", value:"MS23-5002387");
  script_xref(name:"IAVA", value:"2023-A-0296");

  script_name(english:"Security Updates for Outlook (June 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing a security update. It is, therefore, affected
by a remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized
arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002382");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002387");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002382
  -KB5002387");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-33131");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS23-06';
var kbs = make_list(
  '5002382',
  '5002387'
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var vuln = FALSE;

var installs = get_kb_list('SMB/Office/Outlook/*/ProductPath');
if (isnull(installs))
  audit(AUDIT_NOT_INST, 'Microsoft Outlook');

var sp2013 = get_kb_item('SMB/Office/2013/SP');

foreach var install (keys(installs))
{
  var version = install - 'SMB/Office/Outlook/' - '/ProductPath';
  var path = installs[install];
  var base_path = tolower(path) - 'outlook.exe';

  # outlook.exe did not actually get updated for 2013
  if (version =~ "^15.0" && !isnull(sp2013) && sp2013 == 1 && hotfix_check_fversion(path:base_path, file:'emsmdb32.dll', version:'15.0.5559.1000', min_version:'15.0.4000.0', bulletin:bulletin, kb:'5002382', product:'Microsoft Outlook 2013 SP1') == HCF_OLDER)
    vuln = TRUE;
  if (version =~ "^16.0" && hotfix_check_fversion(path:base_path, file:'outlook.exe', version:'16.0.5395.1000', channel:'MSI', channel_product:'Outlook', bulletin:bulletin, kb:'5002387', product:'Microsoft Outlook 2016') == HCF_OLDER)
    vuln = TRUE;
}

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
