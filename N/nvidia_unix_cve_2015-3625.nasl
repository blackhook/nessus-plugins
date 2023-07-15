#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84621);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2015-3625");

  script_name(english:"NVIDIA Graphics Driver Pointer Dereference Privilege Escalation (Unix / Linux)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a driver installed that is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA graphics driver installed on the remote host is affected by
a privilege escalation vulnerability, due to a pointer dereferencing
flaw in the kernel module, which allows a local attacker to gain
complete control of the system.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3693");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate video driver according to the vendor's
advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/08");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-3625");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'352', 'fixed_version':'352.09'},
  {'min_version':'346', 'fixed_version':'346.72'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);