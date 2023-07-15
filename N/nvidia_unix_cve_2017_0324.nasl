#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97385);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id(
    "CVE-2017-0309",
    "CVE-2017-0310",
    "CVE-2017-0311",
    "CVE-2017-0318",
    "CVE-2017-0321"
  );

  script_name(english:"NVIDIA Linux GPU Display Driver 304.x < 304.135 / 340.x < 340.102 / 361.x < 361.119 / 375.x < 375.39 / 378.x < 378.13 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Linux host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Linux host is 304.x prior to 304.135, 340.x prior to 340.102, 361.x
prior to 361.119, 375.x prior to 375.39, or 378.x prior to 378.13.
It is, therefore, affected by multiple vulnerabilities:

  - Multiple integer overflow conditions exist in the kernel
    mode layer handler that allow a local attacker to cause
    a denial of service condition or the execution of
    arbitrary code. (CVE-2017-0309)

  - A flaw exists in the kernel mode layer handler due to
    improper access controls that allows a local attacker to
    cause a denial of service condition. (CVE-2017-0310)

  - A flaw exists in the kernel mode layer handler due to
    improper access controls that allows a local attacker to
    cause a denial of service condition or the execution of
    arbitrary code. (CVE-2017-0311)

  - A flaw exists in the kernel mode layer handler due to
    improper validation of an input parameter. A local
    attacker can exploit this to cause a denial of service
    condition. (CVE-2017-0318)

  - A NULL pointer dereference flaw exists in the
    kernel mode layer handler due to improper validation of
    certain input. A local attacker can exploit this to
    cause a denial of service condition or potentially
    execute arbitrary code. (CVE-2017-0321)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4398");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 304.135 / 340.102 /
361.119 / 375.39 / 378.13 or later in accordance with the vendor
advisory.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0321");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");

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
  {'min_version':'378', 'fixed_version':'378.13'},
  {'min_version':'375', 'fixed_version':'375.39'},
  {'min_version':'361', 'fixed_version':'361.119'},
  {'min_version':'340', 'fixed_version':'340.102'},
  {'min_version':'304', 'fixed_version':'304.135'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);