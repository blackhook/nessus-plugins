#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100258);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2017-0350", "CVE-2017-0351", "CVE-2017-0352");
  script_bugtraq_id(98393, 98475);

  script_name(english:"NVIDIA Linux GPU Display Driver 375.x < 375.66 / 381.x < 381.22 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Linux host is 375.x prior to 375.66 or 381.x prior to 381.22. It is,
therefore, affected by multiple vulnerabilities:

  - A flaw exists in the kernel mode layer handler due to
    improper validation of user-supplied input before it
    is used in offset calculations. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges. (CVE-2017-0350)

  - A NULL pointer dereference flaw exists in the kernel
    mode layer handler due to improper validation of
    user-supplied input. A local attacker can exploit this
    to cause a denial of service condition or potentially to
    gain elevated privileges. (CVE-2017-0351)

  - A flaw exists in the GPU firmware due to incorrect
    access control that may allow CPU software to access
    sensitive GPU control registers. A local attacker can
    exploit this to gain elevated privileges.
    (CVE-2017-0352)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4462");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 375.66 / 381.22 or later
in accordance with the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0352");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nvidia_unix_driver_detect.nbin");
  script_require_keys("NVIDIA_UNIX_Driver/Version");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info();

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version':'381', 'fixed_version':'381.22'},
  {'min_version':'375', 'fixed_version':'375.66'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);