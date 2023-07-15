##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163399);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-28181",
    "CVE-2022-28182",
    "CVE-2022-28183",
    "CVE-2022-28184",
    "CVE-2022-28185",
    "CVE-2022-28186",
    "CVE-2022-28187",
    "CVE-2022-28188",
    "CVE-2022-28189",
    "CVE-2022-28190"
  );
  script_xref(name:"IAVA", value:"2022-A-0281");

  script_name(english:"NVIDIA Windows GPU Display Driver (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by a vulnerability:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer, where an unprivileged 
    regular user on the network can cause an out-of-bounds write through a specially crafted shader, which may lead 
    to code execution, denial of service, escalation of privileges, information disclosure, and data tampering. The 
    scope of the impact may extend to other components. (CVE-2022-28181)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the DirectX11 user mode driver (nvwgf2um/x.dll), 
    where an unauthorized attacker on the network can cause an out-of-bounds write through a specially crafted shader, 
    which may lead to code execution to cause denial of service, escalation of privileges, information disclosure, and 
    data tampering. The scope of the impact may extend to other components. (CVE-2022-28182)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer, where an unprivileged 
    regular user can cause an out-of-bounds read, which may lead to denial of service and information disclosure.
    (CVE-2022-28183)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where an unprivileged regular user can access administrator-privileged registers, which may lead to 
    denial of service, information disclosure, and data tampering. (CVE-2022-28184)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the ECC layer, where an unprivileged regular user
    can cause an out-of-bounds write, which may lead to denial of service and data tampering. (CVE-2022-28185)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where the product receives input or data, but does not validate or incorrectly validates that the 
    input has the properties that are required to process the data safely and correctly, which may lead to denial of 
    service or data tampering. (CVE-2022-28186)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys), where the 
    memory management software does not release a resource after its effective lifetime has ended, which may lead to 
    denial of service. (CVE-2022-28187)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where the product receives input or data, but does not validate or incorrectly validates that the 
    input has the properties that are required to process the data safely and correctly, which may lead to denial of 
    service. (CVE-2022-28188)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where a NULL pointer dereference may lead to a system crash. (CVE-2022-28189)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape, where improper input validation can cause denial of service. (CVE-2022-28190)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5353");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28181");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-28182");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

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
  {'min_version': '450', 'fixed_version': '453.51', 'gpumodel':'tesla'},
  {'min_version': '470', 'fixed_version': '473.47', 'gpumodel':['nvs', 'quadro', 'tesla']},
  {'min_version': '510', 'fixed_version': '512.77', 'gpumodel':'geforce'},
  {'min_version': '510', 'fixed_version': '512.96', 'gpumodel':'studio'},
  {'min_version': '510', 'fixed_version': '512.78', 'gpumodel':['quadro', 'nvs', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
