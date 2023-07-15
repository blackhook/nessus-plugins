#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158892);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/15");

  script_cve_id("CVE-2022-21815");
  script_xref(name:"IAVA", value:"2022-A-0102");

  script_name(english:"NVIDIA Windows GPU Display Driver (February 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by a vulnerability:

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer (nvlddmkm.sys) handler for
    private IOCTLs where a NULL pointer dereference in the kernel, created within user mode code, may lead to a denial
    of service in the form of a system crash. (CVE-2022-21815)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/5312");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21815");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/03/14");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '450', 'fixed_version': '453.37', 'gpumodel':'tesla'},
  {'min_version': '470', 'fixed_version': '472.98', 'gpumodel':['geforce', 'nvs', 'quadro', 'tesla']},
  {'min_version': '473', 'fixed_version': '473.04', 'gpumodel':'geforce'},
  {'min_version': '510', 'fixed_version': '511.65', 'gpumodel':['geforce', 'studio', 'quadro', 'nvs', 'tesla']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
