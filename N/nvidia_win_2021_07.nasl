#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(152124);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/09");

  script_cve_id(
    "CVE-2021-1089",
    "CVE-2021-1090",
    "CVE-2021-1091",
    "CVE-2021-1092",
    "CVE-2021-1093",
    "CVE-2021-1094",
    "CVE-2021-1095",
    "CVE-2021-1096"
  );
  script_xref(name:"IAVB", value:"2021-B-0042");

  script_name(english:"NVIDIA Windows GPU Display Driver (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in nvidia-smi where an uncontrolled DLL
  loading path may lead to arbitrary code execution, denial of service, information disclosure, and data 
  tampering. (CVE-2021-1089)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer 
  (nvlddmkm.sys) handler for control calls where the software reads or writes to a buffer by using an index
  or pointer that references a memory location after the end of the buffer, which may lead to data tampering
  or denial of service. (CVE-2021-1090)

  - NVIDIA GPU Display driver for Windows contains a vulnerability where an unprivileged user can create a 
  file hard link that causes the driver to overwrite a file that requires elevated privilege to modify, which
  could lead to data loss or denial of service. (CVE-2021-1091)
    
Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1edc8112");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}
include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '390.0', 'fixed_version': '392.67', 'gpumodel': ['nvs', 'quadro']},
  {'min_version': '418.0', 'fixed_version': '427.48', 'gpumodel': 'tesla'},
  {'min_version': '450.0', 'fixed_version': '453.10', 'gpumodel': ['nvs', 'quadro', 'tesla']},
  {'min_version': '460.0', 'fixed_version': '462.96', 'gpumodel': ['nvs', 'quadro', 'tesla']},
  {'min_version': '470.0', 'fixed_version': '471.41', 'gpumodel': ['geforce', 'nvs', 'quadro', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
