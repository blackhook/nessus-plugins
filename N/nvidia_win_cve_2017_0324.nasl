#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97386);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2017-0308",
    "CVE-2017-0309",
    "CVE-2017-0310",
    "CVE-2017-0311",
    "CVE-2017-0312",
    "CVE-2017-0313",
    "CVE-2017-0314",
    "CVE-2017-0315",
    "CVE-2017-0317",
    "CVE-2017-0319",
    "CVE-2017-0320",
    "CVE-2017-0321",
    "CVE-2017-0322",
    "CVE-2017-0323",
    "CVE-2017-0324"
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 375.x < 376.67 / 378.x < 378.52 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 375.x prior to 376.67 or 378.x prior to 378.52.
It is, therefore, affected by multiple vulnerabilities :

  - Multiple overflow conditions exist in the kernel mode
    layer handler (nvlddmkm.sys) for DxgkDdiEscape due to a
    failure to properly calculate the input buffer size. A
    local attacker can exploit these to cause a denial of
    service condition or the execution of arbitrary code.
    (CVE-2017-0308, CVE-2017-0324)

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

  - An overflow condition exists in the kernel mode layer
    handler for DxgDdiEscape ID 0x100008B due to improper
    validation of input before setting the limits for a
    loop. A local attacker can exploit this to cause a
    denial of service condition or potentially gain elevated
    privileges. (CVE-2017-0312)

  - Multiple out-of-bounds write flaws exist within the
    DxgkDdiSubmitCommandVirtual() function in the kernel
    mode layer handler due to improper validation of certain
    size and length values. A local attacker can exploit
    these to cause a denial of service condition or the
    execution of arbitrary code. (CVE-2017-0313,
    CVE-2017-0314)

  - A flaw exists in the kernel mode layer handler for
    DxgkDdiEscape due to accessing an invalid object
    pointer that allows a local attacker to execute
    arbitrary code. (CVE-2017-0315)

  - A flaw exists in the NVIDIA GPU and GeForce Experience
    Installer due to improper file permissions on the
    package extraction path. A local attacker can exploit
    this to manipulate extracted files and thereby
    potentially gain elevated privileges. (CVE-2017-0317)

  - Multiple flaws exist in the kernel mode layer handler due
    to improper handling of unspecified values that allow a
    local attacker to cause a denial of service condition.
    (CVE-2017-0319, CVE-2017-0320)

  - Multiple NULL pointer dereference flaws exist in the
    kernel mode layer handler due to improper validation of
    certain input. A local attacker can exploit these to
    cause a denial of service condition or potentially
    execute arbitrary code. (CVE-2017-0321, CVE-2017-0323)

  - An array-indexing error exists in the kernel mode layer
    handler due to improper validation of certain input. A
    local attacker can exploit this to cause a denial of
    service condition or gain elevated privileges.
    (CVE-2017-0322)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4398");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 376.67 / 378.52 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0308");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/02/24");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:nvidia:gpu_driver");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 Tenable Network Security, Inc.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '375.0', 'fixed_version': '376.67'},
  {'min_version': '375.0', 'fixed_version': '376.84', 'name': 'tesla'},
  {'min_version': '378.0', 'fixed_version': '378.52'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
