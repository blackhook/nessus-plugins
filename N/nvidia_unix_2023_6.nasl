#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(177833);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/07/06");

  script_cve_id("CVE-2023-25515", "CVE-2023-25516");
  script_xref(name:"IAVA", value:"2023-A-0323");

  script_name(english:"NVIDIA Linux GPU Display Driver (Jun 2023)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
the following vulnerabilities:

  - NVIDIA Jetson contains a vulnerability in CBoot, where the PCIe controller is initialized without IOMMU,
    which may allow an attacker with physical access to the target device to read and write to arbitrary
    memory. A successful exploit of this vulnerability may lead to code execution, denial of service,
    information disclosure, and loss of integrity. (CVE-2023-25515)

  - An integer overflow vulnerability in the kernel mode layer that can result in information disclosure or
    denial of service. (CVE-2023-25516)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5468");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25515");

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
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version", "NVIDIA_UNIX_Driver/GPU_Model", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'450', 'fixed_version':'450.248.02', 'gpumodel':'tesla'},
  {'min_version':'470', 'fixed_version':'470.199.02', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'525', 'fixed_version':'525.125.06', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
  {'min_version':'535', 'fixed_version':'535.54.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla', 'rtx']},
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
