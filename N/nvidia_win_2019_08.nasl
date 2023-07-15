#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133307);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2019-5685");
  script_xref(name:"IAVA", value:"2019-A-0063-S");

  script_name(english:"NVIDIA Windows GPU Display Driver (August 2019)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA GPU display driver software on the remote host is missing
a security update. It is, therefore, affected by an out of bounds
access vulnerability due to a shader local temporary array, which may
lead to denial of service or code execution.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4841");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the
vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/29");

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
  {'min_version': '430.0', 'fixed_version': '431.60', 'gpumodel': 'geforce'},
  {'min_version': '430.0', 'fixed_version': '431.70', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '418.0', 'fixed_version': '426.00', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '410.0', 'fixed_version': '412.40', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '390.0', 'fixed_version': '392.56', 'gpumodel': ['quadro', 'nvs']},
  {'min_version': '418.0', 'fixed_version': '426.00', 'gpumodel': 'tesla'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
