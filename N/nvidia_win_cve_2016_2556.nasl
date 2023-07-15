#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90119);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id("CVE-2016-2556", "CVE-2016-2557", "CVE-2016-2558");

  script_name(english:"NVIDIA Graphics Driver 340.x < 341.95 / 352.x < 354.74 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA graphics driver installed on the remote
Windows host is 340.x prior to 341.95 or 352.x prior to 354.74. It
is, therefore, affected by multiple vulnerabilities :

  - A privilege escalation vulnerability exists due to a
    kernel driver escape. A local attacker can exploit this
    to gain unauthorized access to restricted functionality,
    potentially allowing the execution of arbitrary code.
    (CVE-2016-2556)

  - An information disclosure vulnerability exists due to an
    out-of-bounds read error. A local attacker can exploit
    this to read arbitrary information from memory.
    (CVE-2016-2557)

  - An unspecified untrusted pointer flaw exists that allows
    a local attacker to cause a denial of service condition
    or the execution of arbitrary code. (CVE-2016-2558)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4059");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4060");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4061");
  # http://us.download.nvidia.com/Windows/341.95/341.95-win8-win7-winvista-desktop-release-notes.pdf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cb06842");
  # https://drivers.softpedia.com/get/GRAPHICS-BOARD/NVIDIA/NVIDIA-GeForce-Graphics-Driver-34195-for-Windows-10-64-bit.shtml
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c2cff15a");
  script_set_attribute(attribute:"see_also", value:"http://www.get-top-news.com/news-11914735.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to video driver version 341.95 / 354.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2558");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/23");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '340.0', 'fixed_version': '341.95'},
  {'min_version': '352.0', 'fixed_version': '354.74'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
