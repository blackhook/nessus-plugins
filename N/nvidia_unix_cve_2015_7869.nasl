#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87411);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2015-7869");

  script_name(english:"NVIDIA Graphics Driver NVAPI Support Layer Integer Overflow Privilege Escalation (Unix / Linux)");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The NVIDIA graphics driver installed on the remote host is affected
by a privilege escalation vulnerability in the NVAPI support layer due
to multiple unspecified integer overflow conditions in the underlying
kernel mode driver. A local attacker can exploit this to gain access
to uninitialized or out-of-bounds memory, resulting in possible
information disclosure, denial of service, or the gaining of elevated
privileges.");
  # https://packetstormsecurity.com/files/134428/Ubuntu-Security-Notice-USN-2814-1.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a143cf56");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/3808");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the appropriate video driver version according to the
vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
    script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-7869");

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
  {'min_version':'358', 'fixed_version':'358.16'},
  {'min_version':'352', 'fixed_version':'352.63'},
  {'min_version':'340', 'fixed_version':'340.96'},
  {'min_version':'304', 'fixed_version':'304.131'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);