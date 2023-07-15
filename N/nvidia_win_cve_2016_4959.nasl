#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93912);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2016-3161",
    "CVE-2016-4959",
    "CVE-2016-4960",
    "CVE-2016-4961",
    "CVE-2016-5025",
    "CVE-2016-5852"
  );

  script_name(english:"NVIDIA Graphics Driver 340.x < 341.96 / 352.x < 354.99 / 361.x < 362.77 / 367.x < 368.39 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA graphics driver installed on the remote
Windows host is 340.x prior to 341.96, 352.x prior to 354.99, 361.x
prior to 362.77, or 367.x prior to 368.39. It is, therefore, affected 
by multiple vulnerabilities :

  - A privilege escalation vulnerability exists in GFE
    GameStream due to an unquoted search path. A local
    attacker can exploit this, via a malicious executable in
    the root path, to elevate privileges. (CVE-2016-3161)

  - A denial of service vulnerability exists due to a NULL
    pointer dereference flaw. An unauthenticated, remote
    attacker can exploit this to cause a crash.
    (CVE-2016-4959)

  - A privilege escalation vulnerability exists in the
    NVStreamKMS.sys driver due to improper sanitization of
    user-supplied data passed via API entry points. A local
    attacker can exploit this to gain elevated privileges.
    (CVE-2016-4960)

  - A denial of service vulnerability exists in the
    NVStreamKMS.sys driver due to improper handling of
    parameters. An unauthenticated, remote attacker can
    exploit this to cause a crash. (CVE-2016-4961)

  - A denial of service vulnerability exists in the NVAPI
    support layer due to improper sanitization of
    parameters. An unauthenticated, remote attacker can
    exploit this to cause a crash. (CVE-2016-5025)

  - A privilege escalation vulnerability exists in the
    NVTray plugin due to an unquoted search path. A local
    attacker can exploit this, via a malicious executable in
    the root path, to elevate privileges. (CVE-2016-5852)

Note that CVE-2016-3161, CVE-2016-4960, CVE-2016-4961, and
CVE-2016-5852 only affect systems which also have GeForce Experience
software installed.");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4213");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 341.96 / 354.99 / 362.77
/ 368.39 or later. Alternatively, for CVE-2016-4959, apply the
mitigation referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5852");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

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
  {'min_version': '367.0', 'fixed_version': '368.39'},
  {'min_version': '361.0', 'fixed_version': '362.77'},
  {'min_version': '352.0', 'fixed_version': '354.99'},
  {'min_version': '340.0', 'fixed_version': '341.96'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
