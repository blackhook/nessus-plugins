#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168370);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2022-34669",
    "CVE-2022-34671",
    "CVE-2022-34672",
    "CVE-2022-34678",
    "CVE-2022-34681",
    "CVE-2022-34683",
    "CVE-2022-42266"
  );
  script_xref(name:"IAVA", value:"2022-A-0504");

  script_name(english:"NVIDIA Windows GPU Display Driver (Nov 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the user mode layer, where an
    unprivileged regular user can access or modify system files or other files that are critical to the
    application, which may lead to code execution, denial of service, escalation of privileges, information
    disclosure, or data tampering. (CVE-2022-34669)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the user mode layer, where an
    unprivileged regular user can cause an out-of-bounds write, which may lead to code execution, denial of
    service, escalation of privileges, information disclosure, or data tampering. (CVE-2022-34671)

  - NVIDIA Control Panel for Windows contains a vulnerability where an unauthorized user or an unprivileged
    regular user can compromise the security of the software by gaining privileges, reading sensitive
    information, or executing commands. (CVE-2022-34672)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5415
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a7a9b79");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var os_version = get_kb_item('SMB/WindowsVersion');

# Windows 10 and 11: fix = 474.04
# Windows 7 and 8.x: fix = 474.06
# Unknown, we set the higher version just in case
var fixed_version_470;
if (!empty_or_null(os_version) && os_version == '10')
  fixed_version_470 = '474.04';
else
  fixed_version_470 = '474.06';

var constraints = [
  {'min_version': '450', 'fixed_version': '453.94', 'gpumodel':'tesla'},
  {'min_version': '470', 'fixed_version': fixed_version_470, 'gpumodel':'geforce'},
  {'min_version': '470', 'fixed_version': '474.04', 'gpumodel':['nvs', 'quadro', 'tesla']},
  {'min_version': '510', 'fixed_version': '513.91', 'gpumodel':['nvs', 'quadro', 'tesla']},
  {'min_version': '515', 'fixed_version': '517.71', 'gpumodel':['nvs', 'quadro', 'tesla']},
  {'min_version': '525', 'fixed_version': '526.98', 'gpumodel':['studio', 'geforce']},
  {'min_version': '525', 'fixed_version': '527.27', 'gpumodel':['nvs', 'quadro']},
  # R525 Update available on December 1, 2022
  {'min_version': '525', 'fixed_version': '527.41', 'gpumodel':'tesla'},
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
