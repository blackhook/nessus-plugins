#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(168369);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2022-34670",
    "CVE-2022-34673",
    "CVE-2022-34674",
    "CVE-2022-34675",
    "CVE-2022-34677",
    "CVE-2022-34679",
    "CVE-2022-34680",
    "CVE-2022-34682",
    "CVE-2022-34684",
    "CVE-2022-42254",
    "CVE-2022-42255",
    "CVE-2022-42256",
    "CVE-2022-42257",
    "CVE-2022-42258",
    "CVE-2022-42259",
    "CVE-2022-42260",
    "CVE-2022-42261",
    "CVE-2022-42262",
    "CVE-2022-42263",
    "CVE-2022-42264",
    "CVE-2022-42265"
  );
  script_xref(name:"IAVA", value:"2022-A-0504");

  script_name(english:"NVIDIA Linux GPU Display Driver (Nov 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    unprivileged regular user can cause truncation errors when casting a primitive to a primitive of smaller
    size causes data to be lost in the conversion, which may lead to denial of service or information
    disclosure. (CVE-2022-34670)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    out-of-bounds read may lead to denial of service, information disclosure, or data tampering.
    (CVE-2022-34676)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler, where an
    Integer overflow may lead to denial of service or information disclosure. (CVE-2022-42263)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5415
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4a7a9b79");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-34670");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/02");

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
  {'min_version':'390', 'fixed_version':'390.157', 'gpumodel':['geforce', 'nvs', 'quadro']},
  {'min_version':'450', 'fixed_version':'450.216.04', 'gpumodel':'tesla'},
  {'min_version':'470', 'fixed_version':'470.161.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'510', 'fixed_version':'510.108.03', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'515', 'fixed_version':'515.86.01', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version':'525', 'fixed_version':'525.60.11', 'gpumodel':['geforce', 'nvs', 'quadro']},
  # R525 Update available on December 1, 2022
  {'min_version':'525', 'fixed_version':'525.60.13', 'gpumodel':'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);
  
