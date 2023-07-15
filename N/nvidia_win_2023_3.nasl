#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(174019);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/30");

  script_cve_id(
    "CVE-2023-0181",
    "CVE-2023-0182",
    "CVE-2023-0184",
    "CVE-2023-0186",
    "CVE-2023-0187",
    "CVE-2023-0188",
    "CVE-2023-0191",
    "CVE-2023-0192",
    "CVE-2023-0194",
    "CVE-2023-0195",
    "CVE-2023-0199"
  );
  script_xref(name:"IAVA", value:"2023-A-0169-S");

  script_name(english:"NVIDIA Windows GPU Display Driver (March 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The NVIDIA GPU display driver software on the remote Windows host is missing a vendor-supplied patch.");
  script_set_attribute(attribute:"description", value:
"A display driver installed on the remote Windows host is affected by multiple vulnerabilities, including the following:

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in the kernel mode layer handler,
    which may lead to denial of service, escalation of privileges, information disclosure, and data tampering. (CVE-2023-0184)

  - NVIDIA GPU Display Driver for Windows contains a vulnerability in the kernel mode layer, where an
    out-of-bounds write can lead to denial of service, information disclosure, and data tampering. (CVE-2023-0182)

  - NVIDIA GPU Display Driver for Windows and Linux contains a vulnerability in a kernel mode layer handler,
    where memory permissions are not correctly checked, which may lead to denial of service and data tampering. (CVE-2023-0181)

Note that Nessus has not attempted to exploit these issues but has instead relied only on the driver's
self-reported version number.");
  # https://nvidia.custhelp.com/app/answers/detail/a_id/5452
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1bf0817");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-0192");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/04/07");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var constraints = [
  { 'min_version':'470', 'fixed_version': '474.30', 'gpumodel':['studio', 'rtx', 'nvs', 'quadro', 'geforce', 'tesla'] },
  { 'min_version':'515', 'fixed_version': '518.03', 'gpumodel':['studio', 'rtx', 'nvs', 'quadro', 'tesla'] },
  { 'min_version':'525', 'fixed_version': '528.89', 'gpumodel':['studio', 'rtx', 'nvs', 'quadro', 'tesla'] },
  { 'min_version':'530', 'fixed_version': '531.41', 'gpumodel':['studio', 'rtx', 'nvs', 'quadro', 'geforce']}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
