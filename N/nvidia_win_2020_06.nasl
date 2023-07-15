#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138358);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2020-5962",
    "CVE-2020-5963",
    "CVE-2020-5964",
    "CVE-2020-5965",
    "CVE-2020-5966"
  );
  script_xref(name:"IAVA", value:"2020-A-0290-S");

  script_name(english:"NVIDIA Windows GPU Display Driver (June 2020)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a security update. It is, therefore,
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities:

  - A privilege escalation vulnerability exists in the Control Panel component. An authenticated, local 
    attacker can exploit this via corrupting a system file, to gain privileged access to the system or cause a
    denial of service condition. (CVE-2020-5962)

  - A code execution vulnerability exists in the Inter Process Communication APIs due to improper access 
    control. An authenticated, local attacker can exploit this issue to cause a denial of service condition,
    execute code or disclose potentially sensitive information. (CVE‑2020‑5963)

  - A code execution vulnerability exists in the service host component, in which the application resources
    integrity check may be missed. An authenticated, local attacker can exploit this issue to cause a denial 
    of service condition, execute code or disclose potentially sensitive information. (CVE‑2020‑5964)

  - A denial of service vulnerability exists in the DirectX 11 user mode driver (nvwgf2um/x.dll). An
    authenticated, local attacker can exploit this via a specially crafted shader to cause an out of bounds
    access to cause a denial of service condition. (CVE‑2020‑5965)

  - A NULL pointer dereference vulnerability exists in the kernel mode layer (nvlddmkm.sys) handler for 
    DxgkDdiEscape. An authenticated, local attacker can exploit this to gain privilege access to the system or 
    cause a denial of service condition. (CVE‑2020‑5966)");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4702d9ab");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-5966");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/10");

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
  {'min_version': '450.0', 'fixed_version': '451.48', 'gpumodel': 'geforce'},
  {'min_version': '450.0', 'fixed_version': '451.48', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '440.0', 'fixed_version': '443.18', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '418.0', 'fixed_version': '426.78', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '390.0', 'fixed_version': '392.61', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '450.0', 'fixed_version': '451.48', 'gpumodel': 'tesla'},
  {'min_version': '440.0', 'fixed_version': '443.18', 'gpumodel': 'tesla'},
  {'min_version': '418.0', 'fixed_version': '426.78', 'gpumodel': 'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);