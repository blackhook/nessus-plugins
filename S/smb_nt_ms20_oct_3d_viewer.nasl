#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(141430);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-16918", "CVE-2020-17003");
  script_xref(name:"ZDI", value:"ZDI-20-1246");
  script_xref(name:"CEA-ID", value:"CEA-2020-0126");

  script_name(english:"Microsoft 3D Viewer Base3D Code Execution (October 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The Windows app installed on the remote host is affected by a code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft 3D Viewer app installed on the remote host is affected by a code execution vulnerability when the
Base3D rendering engine improperly handles memory. An attacker who successfully exploited the vulnerability would gain
execution on a victim system.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-16918
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a0fa39f");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-17003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?baf22b1a");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-20-1246/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to app version 7.2009.29132.0 or later via the Microsoft Store.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-16918");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_windows_app_store.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Microsoft.Microsoft3DViewer");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');
include('smb_func.inc');

app = 'Microsoft.Microsoft3DViewer';
win_port = get_kb_item('SMB/transport');
if (!win_port) win_port = 445;

get_install_count(app_name:app, exit_if_zero:TRUE);

app_info = vcf::get_app_info(app:app, port:win_port);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [
  { 'fixed_version' : '7.2009.29132.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
