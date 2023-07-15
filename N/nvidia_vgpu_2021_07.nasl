#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(159485);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/26");

  script_cve_id(
    "CVE-2021-1097",
    "CVE-2021-1098",
    "CVE-2021-1099",
    "CVE-2021-1100",
    "CVE-2021-1101",
    "CVE-2021-1102",
    "CVE-2021-1103"
  );
  script_xref(name:"IAVB", value:"2021-B-0042");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (July 2021)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where it
    improperly validates the length field in a request from a guest. This flaw allows a malicious guest to
    send a length field that is inconsistent with the actual length of the input, which may lead to
    information disclosure, data tampering, or denial of service. (CVE-2021-1097)

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin), where it doesn't
    release some resources during driver unload requests from guests. This flaw allows a malicious guest to
    perform operations by reusing those resources, which may lead to information disclosure, data tampering,
    or denial of service. (CVE-2021-1098)

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (vGPU plugin) that could allow an
    attacker to cause stack-based buffer overflow and put a customized ROP gadget on the stack. Such an attack
    may lead to information disclosure, data tampering, or denial of service. (CVE-2021-1099)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5211");
  script_set_attribute(attribute:"solution", value:
"Update NVIDIA vGPU software to version 8.8, 11.5, 12.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1099");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  { 'min_version' : '418', 'fixed_version' : '418.213',   'fixed_display' : '8.8 (418.213)' },
  { 'min_version' : '450', 'fixed_version' : '450.142',   'fixed_display' : '11.5 (450.142)' },
  { 'min_version' : '460', 'fixed_version' : '460.91.03', 'fixed_display' : '12.3 (460.91.03)' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
