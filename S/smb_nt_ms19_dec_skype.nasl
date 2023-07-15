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
  script_id(132020);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/16");

  script_cve_id("CVE-2019-1490");
  script_xref(name:"MSKB", value:"4534761");
  script_xref(name:"MSFT", value:"MS19-4534761");
  script_xref(name:"IAVA", value:"2019-A-0457");

  script_name(english:"Security Updates for Microsoft Skype for Business (December 2019)");
  script_summary(english:"Checks for Microsoft security updates.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Skype for Business installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Skype for Business installation on the remote host is missing a security update. It is, therefore,
affected by a spoofing vulnerability because the Skype for Business Server does not properly sanitize a specially
crafted request. An authenticated, remote attacker can exploit the vulnerability by sending a specially crafted request
to an affected server. An attacker who successfully exploits this vulnerability can then perform cross-site scripting
attacks on affected systems and run scripts in the security context of the current user. For the vulnerability to be
exploited, a user must click a specially crafted URL that takes the user to a targeted Skype for Business site.");
  # https://support.microsoft.com/en-us/help/4534761/description-of-the-security-update-for-skype-for-business-server-2019
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f618bbd7");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released KB4534761 to address this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1490");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:skype_for_business");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_lync_server_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('audit.inc');
include('install_func.inc');

report = '';

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
get_kb_item_or_exit('SMB/Registry/Enumerated', exit_code:1);

bulletin = 'MS19-12';
app = 'Microsoft Lync';
installs = get_installs(app_name:app);
fix_ver = '7.0.2046.151';
foreach install (installs[1])
{
  version = install['version'];

  if (ver_compare(ver:version, minver:'7.0', fix:fix_ver, strict:FALSE) < 0 && 'Server' >< install['Product'])
  {
    app_label = 'Skype for Business Server 2019';
    report +=
      '\n\n  Product           : ' + app_label +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix_ver;
  }
}

if (empty(report))
  audit(AUDIT_HOST_NOT, 'affected');

replace_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
