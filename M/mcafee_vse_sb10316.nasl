#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(136668);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/02");

  script_cve_id("CVE-2020-7266");
  script_xref(name:"MCAFEE-SB", value:"SB10316");
  script_xref(name:"IAVA", value:"2020-A-0202");

  script_name(english:"McAfee VirusScan Enterprise < 8.8 Patch 14 Hotfix 116778 Privilege Escalation Vulnerability (SB10316)");

  script_set_attribute(attribute:"synopsis", value:
"The antivirus application installed on the remote Windows host is
affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of McAfee VirusScan Enterprise (VSE) installed on the
remote Windows host is prior to 8.8 Patch 14 Hotfix 116778. It is,
therefore, affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"see_also", value:"https://kc.mcafee.com/corporate/index?page=content&id=SB10316");
  script_set_attribute(attribute:"solution", value:
"Upgrade to McAfee VirusScan Enterprise version 8.8 Patch 14 Hotfix 116778.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mcafee_installed.nasl");
  script_require_keys("Antivirus/McAfee/installed");
  script_require_ports(139, 445);

  exit(0);
}

include('misc_func.inc');
include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');

get_kb_item_or_exit('Antivirus/McAfee/installed');

product_name = get_kb_item_or_exit('Antivirus/McAfee/product_name');
product_version = get_kb_item_or_exit('Antivirus/McAfee/product_version');
product_path = get_kb_item_or_exit('Antivirus/McAfee/product_path');

app = 'McAfee VirusScan Enterprise';

if (app >!< product_name)
  audit(AUDIT_INST_VER_NOT_VULN, product_name);

if (product_version !~ '^8\\.8\\.')
  audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version);

patch_14_fix = '8.8.0.2190'; # 8.8 Patch 14 product version
hotpatch_fix = '20.3.0.179'; # Hotfix 116778 mfeann.exe

exe = product_path + 'mfeann.exe';
ver = hotfix_get_fversion(path:exe);

hotfix_handle_error(error_code:ver['error'], file:exe, appname:app, exit_on_fail:TRUE);
hotfix_check_fversion_end();

hotpatch_version = join(sep:'.', ver['value']);

# hotpatch file is vulnerable
if (ver_compare(ver:hotpatch_version, fix:hotpatch_fix, strict:FALSE) < 0)
{
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;

  report = '  Installed version : ' + product_version + '\n'
         + '  Fixed version     : ' + patch_14_fix + ' (8.8 Patch 14 with Hotfix 116778)' + '\n';

  security_report_v4(extra:report, port:port, severity:SECURITY_NOTE);
}
else audit(AUDIT_INST_VER_NOT_VULN, product_name, product_version);
