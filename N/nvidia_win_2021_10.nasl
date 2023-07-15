#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(155842);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/06");

  script_cve_id("CVE-2021-1115", "CVE-2021-1116", "CVE-2021-1117");
  script_xref(name:"IAVB", value:"2021-B-0066");

  script_name(english:"NVIDIA Windows GPU Display Driver (October 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for
    private IOCTLs, where an attacker with local unprivileged system access may cause a NULL pointer dereference, which
    may lead to denial of service in a component beyond the vulnerable component. (CVE-2021-1115)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys), where a
    NULL pointer dereference in the kernel, created within user mode code, may lead to a denial of service in the form
    of a system crash. (CVE-2021-1116)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for
    DxgkDdiEscape, where an attacker through specific configuration and with local unprivileged system access may cause
    improper input validation, which may lead to denial of service. (CVE-2021-1117)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5230");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1116");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1115");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/12/03");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '390.0', 'fixed_version': '392.68', 'gpumodel': ['nvs', 'quadro']},
  {'min_version': '418.0', 'fixed_version': '427.60', 'gpumodel': 'tesla'},
  {'min_version': '450.0', 'fixed_version': '453.23', 'gpumodel': 'tesla'},
  {'min_version': '460.0', 'fixed_version': '463.15', 'gpumodel': ['nvs', 'quadro', 'tesla']},
  {'min_version': '470.0', 'fixed_version': '472.39', 'gpumodel': ['studio', 'geforce', 'nvs', 'quadro']},
  {'min_version': '470.0', 'fixed_version': '472.50', 'gpumodel': 'tesla'},
  {'min_version': '495.0', 'fixed_version': '496.49', 'gpumodel': ['geforce', 'nvs', 'quadro']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
