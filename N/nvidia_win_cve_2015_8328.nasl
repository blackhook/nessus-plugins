#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87412);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2015-7865",
    "CVE-2015-7866",
    "CVE-2015-7869",
    "CVE-2015-8328"
  );
  script_bugtraq_id(83873);
  script_xref(name:"EDB-ID", value:"38792");

  script_name(english:"NVIDIA Graphics Driver 340.x < 341.92 / 352.x < 354.35 / 358.x < 358.87 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA graphics driver installed on the remote
Windows host is 340.x prior to 341.92, 352.x prior to 354.35, or 358.x
prior to 358.87. It is, therefore, affected by multiple
vulnerabilities :

  - A privilege escalation vulnerability exists in the 
    Stereoscopic 3D Driver Service due to improper
    restriction of access to the 'stereosvrpipe' named pipe.
    An adjacent attacker can exploit this to execute
    arbitrary command line arguments, resulting in an
    escalation of privileges. (CVE-2015-7865)

  - A privilege escalation vulnerability exists due to an
    unquoted Windows search path issue in the Smart Maximize
    Helper (nvSmartMaxApp.exe). A local attacker can exploit
    this to escalate privileges. (CVE-2015-7866)

  - Multiple privilege escalation vulnerabilities exist in
    the NVAPI support layer due to multiple unspecified
    integer overflow conditions in the underlying kernel
    mode driver. A local attacker can exploit these issues
    to gain access to uninitialized or out-of-bounds memory,
    resulting in an escalation of privileges.
    (CVE-2015-7869, CVE-2015-8328)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3806");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3807");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3808");
  script_set_attribute(attribute:"solution", value:
"Upgrade to video driver version 341.92 / 354.35 / 358.87 or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7865");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2015/11/13");
  script_set_attribute(attribute:"patch_publication_date",value:"2015/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");
  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '358.0', 'fixed_version': '358.87'},
  {'min_version': '352.0', 'fixed_version': '354.35'},
  {'min_version': '340.0', 'fixed_version': '341.92'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
