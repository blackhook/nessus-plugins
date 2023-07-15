##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163886);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-31607", "CVE-2022-31608", "CVE-2022-31615");
  script_xref(name:"IAVA", value:"2022-A-0309");

  script_name(english:"NVIDIA Linux GPU Display Driver (Aug 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer (nvidia.ko), where a local 
    user with basic capabilities can cause improper input validation, which may lead to denial of service, escalation 
    of privileges, data tampering, and limited information disclosure. (CVE-2022-31607)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in an optional D-Bus configuration file,
    where a local user with basic capabilities can impact protected D-Bus endpoints, which may lead to code execution, 
    denial of service, escalation of privileges, information disclosure, and data tampering.
    (CVE-2022-31608)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where a local user with 
    basic capabilities can cause a null-pointer dereference, which may lead to denial of service. (CVE-2022-31615)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5383/~/security-bulletin%3A-nvidia-gpu-display-driver---august-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0968b96b");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31607");

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
  {'min_version':'390', 'fixed_version':'390.154', 'gpumodel':['geforce', 'nvs', 'quadro']},
  {'min_version':'450', 'fixed_version':'450.203.03', 'gpumodel':'tesla'},
  {'min_version':'470', 'fixed_version':'470.141.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'510', 'fixed_version':'510.85.02', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'515', 'fixed_version':'515.65.01', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  