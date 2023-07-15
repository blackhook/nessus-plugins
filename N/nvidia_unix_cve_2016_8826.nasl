#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96001);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2016-8826");
  script_bugtraq_id(94957);
  script_name(english:"NVIDIA Linux GPU Display Driver 304.x < 304.134 / 340.x < 340.101 / 361.x < 361.107 / 375.x < 375.26 GPU Interrupt Saturation DoS");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Linux host is 304.x prior to 304.134, 340.x prior to 340.101, 361.x
prior to 361.107 (Tesla P100), 375.x prior to 375.20 (Tesla P100), or
375.x prior to 370.26. It is, therefore, affected by a denial of
service vulnerability due to a flaw in the kernel mode layer
(nvidia.ko) driver. A local attacker can exploit this to cause GPU
interrupt saturation, resulting in a denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4278");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 304.134 / 340.101 /
361.107 / 375.20 (Tesla P100 Series) / 375.26 or later in accordance
with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8826");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'375', 'fixed_version':'375.26'},
  {'min_version':'361', 'fixed_version':'361.107'},
  {'min_version':'340', 'fixed_version':'340.101'},
  {'min_version':'304', 'fixed_version':'304.134'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);