##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145034);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/11");

  script_cve_id("CVE-2021-1052", "CVE-2021-1053");
  script_xref(name:"IAVB", value:"2021-B-0005");

  script_name(english:"NVIDIA Linux GPU Display (January 2021)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer 
  (nvlddmkm.sys) handler for DxgkDdiEscape or IOCTL in which user-mode clients can access legacy privileged
  APIs, which may lead to denial of service, escalation of privileges, and information disclosure. (CVE‑2021‑1052)
  
  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer (nvlddmkm.sys)
  handler for DxgkDdiEscape or IOCTL in which improper validation of a user pointer may lead to denial of 
  service. (CVE‑2021‑1053)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5142
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce9736e3");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1052");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'450', 'fixed_version':'450.102.04', 'gpumodel':['geforce', 'nvs','quadro', 'tesla']},
  {'min_version':'460', 'fixed_version':'460.32.03', 'gpumodel':['geforce', 'nvs','quadro', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);