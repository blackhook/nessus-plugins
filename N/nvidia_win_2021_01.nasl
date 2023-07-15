##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145035);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/11");

  script_cve_id(
    "CVE-2021-1051",
    "CVE-2021-1052",
    "CVE-2021-1053",
    "CVE-2021-1054",
    "CVE-2021-1055"
  );
  script_xref(name:"IAVB", value:"2021-B-0005");

  script_name(english:"NVIDIA Windows GPU Display Driver (January 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities:
    
    - NVIDIA GPU Display Driver contains a vulnerability in the NVIDIA Control Panel component, in which an 
    attacker with local system access can corrupt a system file, which may lead to denial of service or 
    escalation of privileges (CVE-2020-5962).

    - NVIDIA CUDA Driver contains a vulnerability in the Inter Process Communication APIs, in which improper
     access control may lead to code execution, denial of service, or information disclosure (CVE-2020-5963).

    - NVIDIA GPU Display Driver contains a vulnerability in the service host component, in which the 
    application resources integrity check may be missed. Such an attack may lead to code execution, 
    denial of service or information disclosure (CVE-2020-5964).
  
  Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
  self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4702d9ab");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1052");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1051");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}
include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2) 
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '390.0', 'fixed_version': '392.63', 'gpumodel': ['nvs', 'quadro']},
  {'min_version': '418.0', 'fixed_version': '427.11', 'gpumodel': 'tesla'},
  {'min_version': '450.0', 'fixed_version': '452.77', 'gpumodel': ['quadro', 'nvs', 'tesla']},
  {'min_version': '460.0', 'fixed_version': '461.09', 'gpumodel': ['geforce', 'quadro', 'nvs', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_HOLE
);