#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174017);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2023-0180",
    "CVE-2023-0181",
    "CVE-2023-0183",
    "CVE-2023-0184",
    "CVE-2023-0185",
    "CVE-2023-0187",
    "CVE-2023-0188",
    "CVE-2023-0189",
    "CVE-2023-0190",
    "CVE-2023-0191",
    "CVE-2023-0194",
    "CVE-2023-0195",
    "CVE-2023-0198",
    "CVE-2023-0199"
  );
  script_xref(name:"IAVA", value:"2023-A-0169-S");

  script_name(english:"NVIDIA Linux GPU Display Driver (March 2023)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, which may
    lead to code execution, denial of service, escalation of privileges, information disclosure, and data
    tampering. (CVE-2023-0189)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, which may
    lead to denial of service, escalation of privileges, information disclosure, and data tampering. (CVE-2023-0184)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in a kernel mode layer handler, where memory
    permissions are not correctly checked, which may lead to denial of service and data tampering. (CVE-2023-0181)

Note that Nessus has not tested for the issue but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1bf0817");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0189");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/07");

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
  audit(AUDIT_POTENTIAL_VULN);

var constraints = [
  {'min_version':'470', 'fixed_version':'470.182.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'515', 'fixed_version':'515.105.01', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'525', 'fixed_version':'525.105.17', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'530', 'fixed_version':'530.41.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'rtx']},
  {'min_version':'450', 'fixed_version':'450.236.01', 'gpumodel':['tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
