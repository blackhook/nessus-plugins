#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174018);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2023-0180",
    "CVE-2023-0181",
    "CVE-2023-0183",
    "CVE-2023-0185",
    "CVE-2023-0188",
    "CVE-2023-0191",
    "CVE-2023-0192",
    "CVE-2023-0197",
    "CVE-2023-0198"
  );
  script_xref(name:"IAVA", value:"2023-A-0169-S");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (March 2023)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in a kernel mode layer handler, where memory
    permissions are not correctly checked, which may lead to denial of service and data tampering. (CVE-2023-0181)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer where an
    out-of-bounds write can lead to denial of service and data tampering. (CVE-2023-0183)

  - NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer, where sign conversion
    issues may lead to denial of service or information disclosure. (CVE-2023-0185)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1bf0817");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA vGPU Manager software in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0198");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  { 'min_version' : '450', 'fixed_version' : '450.236.03',   'fixed_display' : '11.12 (450.236.03)' },
  { 'min_version' : '470', 'fixed_version' : '470.182.02',   'fixed_display' : '13.7 (470.182.02)' },
  { 'min_version' : '525', 'fixed_version' : '525.105.14',   'fixed_display' : '15.2 (525.105.14)' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
