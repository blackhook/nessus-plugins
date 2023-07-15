#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177834);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2022-34671", "CVE-2023-25515");
  script_xref(name:"IAVA", value:"2023-A-0323");

  script_name(english:"NVIDIA Windows GPU Display Driver (Jun 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, as follows:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the user mode layer, where an unprivileged regular
    user can cause an out-of-bounds write, which may lead to code execution, denial of service, escalation of
    privileges, information disclosure, or data tampering. (CVE-2022-34671)

  - NVIDIA Jetson contains a vulnerability in CBoot, where the PCIe controller is initialized without IOMMU,
    which may allow an attacker with physical access to the target device to read and write to arbitrary
    memory. A successful exploit of this vulnerability may lead to code execution, denial of service,
    information disclosure, and loss of integrity. (CVE-2023-25515)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5468");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34671");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/30");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '525', 'fixed_version': '529.11', 'gpumodel':['quadro', 'nvs', 'rtx', 'tesla']},
  {'min_version': '470', 'fixed_version': '474.44', 'gpumodel':['nvs', 'quadro', 'rtx', 'tesla', 'geforce']},
  {'min_version': '535', 'fixed_version': '536.23', 'gpumodel':'geforce'},
  {'min_version': '535', 'fixed_version': '536.25', 'gpumodel':['quadro', 'rtx', 'nvs', 'tesla']},
  {'min_version': '450', 'fixed_version': '454.23', 'gpumodel':'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
