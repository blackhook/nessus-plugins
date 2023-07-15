##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163400);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id(
    "CVE-2022-28181",
    "CVE-2022-28183",
    "CVE-2022-28184",
    "CVE-2022-28185"
  );
  script_xref(name:"IAVA", value:"2022-A-0281");

  script_name(english:"NVIDIA Linux GPU Display Driver (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an 
    unprivileged regular user on the network can cause an out-of-bounds write through a specially crafted shader, which
    may lead to code execution, denial of service, escalation of privileges, information disclosure, and data 
    tampering. The scope of the impact may extend to other components. (CVE-2022-28181)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where an unprivileged
    regular user can cause an out-of-bounds read, which may lead to denial of service and information disclosure.
    (CVE-2022-28183)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler 
    for DxgkDdiEscape, where an unprivileged regular user can access administrator-privileged registers, which may lead
    to denial of service, information disclosure, and data tampering. (CVE-2022-28184)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the ECC layer, where an unprivileged regular user 
    can cause an out-of-bounds write, which may lead to denial of service and data tampering. (CVE-2022-28185)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5353");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28181");

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
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'390', 'fixed_version':'390.151', 'gpumodel':['geforce', 'nvs', 'quadro']},
  {'min_version':'450', 'fixed_version':'450.191.01', 'gpumodel':'tesla'},
  {'min_version':'470', 'fixed_version':'470.129.06', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'510', 'fixed_version':'510.73.05', 'gpumodel':['geforce', 'nvs', 'quadro']},
  {'min_version':'510', 'fixed_version':'510.73.08', 'gpumodel':'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
