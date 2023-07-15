#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(140596);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1574");
  script_xref(name:"IAVA", value:"2020-A-0361-S");
  script_xref(name:"CEA-ID", value:"CEA-2020-0101");

  script_name(english:"Microsoft Windows WebP Image Extension RCE (August 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a Remote Code Execution Vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Windows 'WebP Image Extension' or 'WebP from Device Manufacturer' app
installed on the remote host is affected by a remote code execution vulnerability.
An unauthenticated, remote attacker can exploit this vulnerability via an specially 
crafted image to execute code and gain control of the system.");
  # https://portal.msrc.microsoft.com/en-US/security-guidance/advisory/CVE-2020-1574
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2638e5b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 1.0.31251.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1574");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft.WebpImageExtension");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('smb_func.inc');

app = 'Microsoft.WebpImageExtension';
win_port = get_kb_item('SMB/transport');
if (!win_port) win_port = 445;

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app, port:win_port);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '1.0.31251.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
