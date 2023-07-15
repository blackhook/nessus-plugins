##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(163882);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/23");

  script_cve_id("CVE-2022-31609", "CVE-2022-31614", "CVE-2022-31618");
  script_xref(name:"IAVA", value:"2022-A-0309");

  script_name(english:"NVIDIA Virtual GPU Manager Multiple Vulnerabilities (August 2022)");

  script_set_attribute(attribute:"synopsis", value:
"A GPU virtualization application installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA Virtual GPU Manager software on the remote host is missing a security update. It is, therefore, affected by
multiple vulnerabilities, including the following:

  - A vulnerability that allows the guest VM to allocate resources for which the guest is not authorized,
    leading to a loss of confidentiality, integrity, and availability. (CVE-2022-31609)

  - A double-free flaw that can be exploited by an attacker with other vulnerabilities to cause a denial of
    service, code execution, or information disclosure. (CVE-2022-31614)

  - A null pointer dereference which can lead to a denial of service. (CVE-2022-31618)
  
Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version 
number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5383/~/security-bulletin%3A-nvidia-gpu-display-driver---august-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0968b96b");
  script_set_attribute(attribute:"solution", value:
"Update NVIDIA vGPU Manager software to version 11.9, 13.4, 14.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31609");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/05");

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
  { 'min_version' : '450', 'fixed_version' : '450.203',   'fixed_display' : '11.9 (450.203)' },
  { 'min_version' : '470', 'fixed_version' : '470.141.05',   'fixed_display' : '13.4 (470.141.05)' },
  { 'min_version' : '510', 'fixed_version' : '510.85.03', 'fixed_display' : '14.2 (510.85.03)' },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
