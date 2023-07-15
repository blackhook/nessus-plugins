#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96002);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2016-8821",
    "CVE-2016-8822",
    "CVE-2016-8823",
    "CVE-2016-8824",
    "CVE-2016-8825",
    "CVE-2016-8826"
  );
  script_bugtraq_id(
    94918,
    94956,
    94957
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 340.x < 342.01 / 375.x < 376.33 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 340.x prior to 342.01 or 375.x prior to 376.33. It is,
therefore, affected by multiple vulnerabilities :

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape due to improper access
    controls. A local attacker can exploit this to access
    arbitrary memory and thereby gain elevated privileges.
    (CVE-2016-8821)

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape IDs 0x600000E, 0x600000F, and
    0x6000010 due to improper validation of user-supplied
    input that is used as an index to an internal array. A
    local attacker can exploit this to corrupt memory,
    resulting in a denial of service condition or an
    escalation of privileges. (CVE-2016-8822)

  - Multiple buffer overflow conditions exist in the kernel
    mode layer (nvlddmkm.sys) handler for DxgDdiEscape due
    to improper validation of an input buffer size. A local
    attacker can exploit these to cause a denial of service
    condition or the execution of arbitrary code.
    (CVE-2016-8823, CVE-2016-8825)

  - A flaw exists in the kernel mode layer (nvlddmkm.sys)
    handler for DxgDdiEscape due to improper access
    controls. A local attacker can exploit this to write to
    restricted portions of the registry and thereby gain
    elevated privileges. (CVE-2016-8824)

  - A flaw exists in the nvlddmkm.sys driver that allows a
    local attacker to cause GPU interrupt saturation,
    resulting in a denial of service condition.
    (CVE-2016-8826)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4278");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 342.01 / 376.33 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8821");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/12/21");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2023 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '340.0', 'fixed_version': '342.01'},
  {'min_version': '375.0', 'fixed_version': '376.33'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
