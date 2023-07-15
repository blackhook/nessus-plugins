##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163398);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-28191", "CVE-2022-28192");
  script_xref(name:"IAVA", value:"2022-A-0281");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (May 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (nvidia.ko), where uncontrolled resource 
    consumption can be triggered by an unprivileged regular user, which may lead to denial of service. (CVE-2022-28191)
  
  - NVIDIA vGPU software contains a vulnerability in the Virtual GPU Manager (nvidia.ko), where it may lead to a 
    use-after-free, which in turn may cause denial of service. This attack is complex to carry out because the 
    attacker needs to have control over freeing some host side resources out of sequence, which requires elevated 
    privileges. (CVE-2022-28192)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5353");
  script_set_attribute(attribute:"solution", value:
"Update NVIDIA vGPU software to version 11.8, 13.3, 14.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28191");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/07/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:virtual_gpu_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_vgpu_manager_installed.nbin");
  script_require_keys("installed_sw/NVIDIA Virtual GPU Manager");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'NVIDIA Virtual GPU Manager');

var constraints = [
  { 'min_version' : '450', 'fixed_version' : '450.191',   'fixed_display' : '11.8 (450.191)' },
  { 'min_version' : '470', 'fixed_version' : '470.129.04',   'fixed_display' : '13.3 (470.129.04)' },
  { 'min_version' : '510', 'fixed_version' : '510.73.06', 'fixed_display' : '14.1 (510.73.06)' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);