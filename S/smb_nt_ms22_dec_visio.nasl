#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169003);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-44695");
  script_xref(name:"MSKB", value:"5002280");
  script_xref(name:"MSKB", value:"5002286");
  script_xref(name:"MSFT", value:"MS22-5002280");
  script_xref(name:"MSFT", value:"MS22-5002286");
  script_xref(name:"IAVA", value:"2022-A-0525-S");

  script_name(english:"Security Updates for Microsoft Visio Products (December 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Visio Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Visio Products are missing a security update. They are, therefore, affected by a remote code execution
vulnerability. An attacker can exploit this to bypass authentication and execute unauthorized arbitrary commands.");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002280");
  script_set_attribute(attribute:"see_also", value:"https://support.microsoft.com/en-us/help/5002286");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released the following security updates to address this issue:  
  -KB5002280
  -KB5002286");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-44695");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visio");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_visio_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible", "SMB/Registry/Enumerated");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('smb_hotfixes_fcheck.inc');

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var bulletin = 'MS22-12';
var kbs = make_list(
  '5002280',  # Visio 2013
  '5002286'   # Visio 2016
);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

var vuln = FALSE;

var installs = get_kb_list('SMB/Office/Visio/*/VisioPath');
if (isnull(installs))
  audit(AUDIT_NOT_INST, 'Microsoft Visio');

var sp2013 = get_kb_item('SMB/Office/Visio/2013/SP');

foreach var install (keys(installs))
{
  var version = install - 'SMB/Office/Visio/' - '/VisioPath';
  var path = installs[install];

  if ('15.0' >< version && !isnull(sp2013) && sp2013 == 1 && hotfix_check_fversion(path:path, file:'visbrgr.dll', version:'15.0.5511.1000', min_version:'15.0.4000.0', bulletin:bulletin, kb:'5002280', product:'Microsoft Visio 2013 SP1') == HCF_OLDER)
    vuln = TRUE;
  if ('16.0' >< version && hotfix_check_fversion(path:path, file:'visbrgr.dll', version:'16.0.5366.1000', channel:'MSI', channel_product:'Visio', bulletin:bulletin, kb:'5002286', product:'Microsoft Visio 2016') == HCF_OLDER)
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
