#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(95370);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2016-8813",
    "CVE-2016-8814",
    "CVE-2016-8815",
    "CVE-2016-8816",
    "CVE-2016-8817",
    "CVE-2016-8818",
    "CVE-2016-8819",
    "CVE-2016-8820"
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 34x.x < 342.00 / 367.x < 369.73 / 367.x < 369.71 (GRID) / 375.x < 375.63 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 34x.x prior to 342.00, 367.x prior to 369.73, 367.x
prior to 369.71 (GRID), or 375.x prior to 375.63. It is, therefore,
affected by multiple vulnerabilities :

  - Multiple privilege escalation vulnerabilities exist in
    the kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to a NULL pointer dereference flaw. A
    local attacker can exploit this to cause a denial of
    service condition or an escalation of privileges.
    (CVE-2016-8813, CVE-2016-8814)

  - Multiple privilege escalation vulnerabilities exist in
    the kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper validation of user-supplied
    input used for the index to an array. A local attacker
    can exploit this to cause a denial of service condition
    or an escalation of privileges. (CVE-2016-8815,
    CVE-2016-8815)

  - A privilege escalation vulnerability exists in the
    kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper validation of user-supplied
    input to the memcpy() function. A local attacker can
    exploit this to cause a buffer overflow, resulting in a
    denial of service condition or an escalation of
    privileges. (CVE-2016-8817)

  - A privilege escalation vulnerability exists in the
    kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper validation of user-supplied
    input. A local attacker can exploit this to cause a
    denial of service condition or an escalation of
    privileges. (CVE-2016-8818)

  - A privilege escalation vulnerability exists in the
    kernel mode layer (nvlddmkm.sys) handler for
    DxgDdiEscape due to improper handling of objects in
    memory. A local attacker can exploit this to cause a
    denial of service condition or an escalation of
    privileges. (CVE-2016-8819)

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape due to a failure to check a
    function return value. A local attacker can exploit this
    to disclose sensitive information or cause a denial of
    service condition. (CVE-2016-8820)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4257");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 342.00 / 369.73 /
369.71 (GRID) / 375.63 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8819");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/28");

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
  {'min_version': '340.0', 'fixed_version': '342.00'},
  {'min_version': '367.0', 'fixed_version': '369.73'},
  {'min_version': '375.0', 'fixed_version': '375.63'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
