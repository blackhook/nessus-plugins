##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(149045);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2021-1074",
    "CVE-2021-1075",
    "CVE-2021-1076",
    "CVE-2021-1077",
    "CVE-2021-1078"
  );
  script_xref(name:"IAVB", value:"2021-B-0027");

  script_name(english:"NVIDIA Windows GPU Display Driver (April 2021)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities:
    
    - NVIDIA Windows GPU Display Driver for Windows, R390 driver branch, contains a vulnerability
      in its installer where an attacker with local system access may replace an application resource
      with malicious files. Such an attack may lead to code execution, escalation of privileges, denial
      of service, or information disclosure (CVE-2021-1074).

    - NVIDIA Windows GPU Display Driver for Windows, all versions, contains a vulnerability in the kernel
      mode layer (nvlddmkm.sys) handler for DxgkDdiEscape where the program dereferences a pointer that 
      contains a location for memory that is no longer valid, which may lead to code execution, denial of 
      service, or escalation of privileges (CVE-2021-1075).

    - NVIDIA GPU Display Driver for Windows and Linux, all versions, contains a vulnerability in the kernel
      mode layer (nvlddmkm.sys or nvidia.ko) where improper access control may lead to denial of service, 
      information disclosure, or data corruption (CVE-2021-1076).
  
  Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
  self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5172
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?651e081d");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1074");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1076");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/28");

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
  {'min_version': '390.0', 'fixed_version': '392.65', 'gpumodel': ['nvs', 'quadro']},
  {'min_version': '418.0', 'fixed_version': '427.33', 'gpumodel': 'tesla'},
  {'min_version': '450.0', 'fixed_version': '452.96', 'gpumodel': ['nvs', 'quadro', 'tesla']},
  {'min_version': '460.0', 'fixed_version': '462.31', 'gpumodel': ['geforce', 'nvs','quadro',  'tesla']},
  {'min_version': '465.0', 'fixed_version': '466.11', 'gpumodel': ['geforce', 'nvs','quadro']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info, 
  constraints:constraints, 
  severity:SECURITY_WARNING
);