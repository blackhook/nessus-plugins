#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(134761);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2020-5957", "CVE-2020-5958");
  script_xref(name:"IAVA", value:"2020-A-0111-S");

  script_name(english:"NVIDIA Windows GPU Display Driver (Feb 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote host is missing
a security update. It is, therefore, affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.

  - A privilege escalation vulnerability exists in NVIDIA Control 
    Panel component. An unauthenticated, local attacker can exploit 
    this, via corrputing a system file, to gain priviledged access 
    to the system.
   
  - A privilege escalation vulnerability exists in NVIDIA Control 
    Panel component. An unauthenticated, local attacker can exploit 
    this, via planting a malicious DLL file, this may lead to 
    code execution, denial of service, or information disclosure.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4996");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5957");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-5958");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '430.0', 'fixed_version': '442.50', 'gpumodel': 'geforce'},
  {'min_version': '440.0', 'fixed_version': '442.50', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '430.0', 'fixed_version': '432.28', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '418.0', 'fixed_version': '426.50', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '390.0', 'fixed_version': '392.59', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '440.0', 'fixed_version': '442.50', 'gpumodel': 'tesla'},
  {'min_version': '418.0', 'fixed_version': '426.50', 'gpumodel': 'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);