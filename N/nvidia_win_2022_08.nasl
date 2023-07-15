##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163887);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-31606",
    "CVE-2022-31610",
    "CVE-2022-31612",
    "CVE-2022-31613",
    "CVE-2022-31616",
    "CVE-2022-31617",
    "CVE-2022-34665",
    "CVE-2022-34666"
  );
  script_xref(name:"IAVA", value:"2022-A-0309");

  script_name(english:"NVIDIA Windows GPU Display Driver (Aug 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by a vulnerability:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where a failure to properly validate data might allow an attacker with basic user capabilities to 
    cause an out-of-bounds access in kernel mode, which could lead to denial of service, information disclosure, 
    escalation of privileges, or data tampering. (CVE-2022-31606)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys),
    where a local user with basic capabilities can cause an out-of-bounds write, which may lead to code execution, 
    denial of service, escalation of privileges, information disclosure, or data tampering. (CVE-2022-31610)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler
    for DxgkDdiEscape, where a local user with basic capabilities can cause an out-of-bounds read, which may lead 
    to a system crash or a leak of internal kernel information. (CVE-2022-31612)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer, where any local user can 
    cause a null-pointer dereference, which may lead to a kernel panic. (CVE-2022-31613)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where a local user with basic capabilities can cause an out-of-bounds read, which may lead to denial
    of service, or information disclosure. (CVE-2022-31616)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys),
    where a local user with basic capabilities can cause an out-of-bounds read, which may lead to code execution, 
    denial of service, escalation of privileges, information disclosure, or data tampering. (CVE-2022-31617)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer, where a local user with 
    basic capabilities can cause a null-pointer dereference, which may lead to denial of service. (CVE-2022-34665)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer, where a local user with 
    basic capabilities can cause a null-pointer dereference, which may lead to denial of service. (CVE-2022-34666)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5383/~/security-bulletin%3A-nvidia-gpu-display-driver---august-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0968b96b");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/05");

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

var constraints = [
  {'min_version': '450', 'fixed_version': '453.64', 'gpumodel':'tesla'},
  {'min_version': '470', 'fixed_version': '472.81', 'gpumodel':'tesla', 'fixed_display':'473.81'},
  {'min_version': '470', 'fixed_version': '473.81', 'gpumodel':['nvs', 'quadro', 'geforce']},
  {'min_version': '510', 'fixed_version': '513.46', 'gpumodel':['nvs', 'quadro', 'tesla']},
  {'min_version': '515', 'fixed_version': '516.94', 'gpumodel':['nvs', 'quadro', 'tesla']},
  {'min_version': '515', 'fixed_version': '515.9999', 'gpumodel':['studio', 'geforce'], 'fixed_display':'See vendor advisory'} 
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);