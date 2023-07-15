#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152123);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id(
    "CVE-2021-1090",
    "CVE-2021-1093",
    "CVE-2021-1094",
    "CVE-2021-1095"
  );
  script_xref(name:"IAVB", value:"2021-B-0042");

  script_name(english:"NVIDIA Linux GPU Display Driver (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer 
  (nvlddmkm.sys) handler for control calls where the software reads or writes to a buffer by using an
  index or pointer that references a memory location after the end of the buffer, which may lead to 
  data tampering or denial of service. (CVE-2021-1090)

  -  NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer 
  (nvlddmkm.sys) handler for DxgkDdiEscape where an out of bounds array access may lead to denial of service
  or information disclosure. (CVE-2021-1094)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer 
  (nvlddmkm.sys) handlers for all control calls with embedded parameters where dereferencing an untrusted
  pointer may lead to denial of service. (CVE-2021-1095)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5211
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1edc8112");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1094");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1090");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/28");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}
include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'390', 'fixed_version':'390.144', 'gpumodel':['quadro', 'nvs']},
  {'min_version':'418', 'fixed_version':'418.211.00', 'gpumodel':'tesla'},
  {'min_version':'450', 'fixed_version':'450.142.00', 'gpumodel':'tesla'},
  {'min_version':'460', 'fixed_version':'460.91.03', 'gpumodel':['geforce', 'nvs','quadro', 'tesla']},
  {'min_version':'470', 'fixed_version':'470.57.02', 'gpumodel':['geforce', 'nvs','quadro', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_NOTE
);
  
