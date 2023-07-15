#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(126049);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2019-5666",
    "CVE-2019-5675",
    "CVE-2019-5676",
    "CVE-2019-5677"
  );

  script_name(english:"NVIDIA Windows GPU Display Driver Multiple Vulnerabilities (May 2019)");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a security update. It is, therefore,
affected by multiple vulnerabilities:

  - An unspecified vulnerability exists in the kernel mode layer (nvvlddmkm.sys) handler for DxgkDdiEscape due to
    improper synchronization of shared data. An authenticated, local attacker can exploit this, to cause a denial of
    service, gain elevated privileges or to disclose potentially sensitive information. (CVE-2019-5675)

  - A binary planting vulnerability exists due to improper path or signature validation. An authenticated, local
    attacker can exploit this, via code execution to gain elevated privileges. (CVE-2019-5676)

  - A memory corruption vulnerability exists in the kernel mode layer (nvlddmkm.sys) handler for DeviceIoControl. An
    authenticated, local attacker can exploit this, to cause a denial of service condition. (CVE-2019-5677)");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/4797
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fd89bc5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5676");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5675");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '430.0', 'fixed_version': '430.64', 'gpumodel': ['geforce', 'quadro', 'nvs']},
  {'min_version': '418.0', 'fixed_version': '425.51', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '410.0', 'fixed_version': '412.36', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '390.0', 'fixed_version': '392.53', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '418.0', 'fixed_version': '425.25', 'gpumodel': 'tesla'},
  {'min_version': '410.0', 'fixed_version': '412.36', 'gpumodel': 'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
