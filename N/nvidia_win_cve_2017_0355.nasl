#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100259);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2017-0341",
    "CVE-2017-0342",
    "CVE-2017-0343",
    "CVE-2017-0344",
    "CVE-2017-0345",
    "CVE-2017-0346",
    "CVE-2017-0347",
    "CVE-2017-0348",
    "CVE-2017-0349",
    "CVE-2017-0353",
    "CVE-2017-0354",
    "CVE-2017-0355"
  );
  script_bugtraq_id(98393, 98475);

  script_name(english:"NVIDIA Windows GPU Display Driver 375.x < 377.35 / 382.x < 382.05 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 375.x prior to 377.35 or 382.x prior to 382.05. It is,
therefore, affected by multiple vulnerabilities :

  - An uninitialized pointer flaw exists in the kernel mode
    layer (nvlddmkm.sys) handler for DxgDdiEscape due to
    improper validation of user-supplied input. A local
    attacker can exploit this to cause a denial of service
    condition or potentially to gain elevated privileges.
    (CVE-2017-0341)

  - An out-of-bounds access error exists in the kernel mode
    layer (nvlddmkm.sys) handler due to certain incorrect
    calculations. A local attacker can exploit this to cause
    a denial of service condition or potentially to gain
    elevated privileges. (CVE-2017-0342)

  - A race condition exists in the kernel mode layer
    (nvlddmkm.sys) handler due to improper synchronization
    of certain functions. A local attacker can exploit this
    to cause a denial of service condition or potentially to
    gain elevated privileges. (CVE-2017-0343)

  - An unspecified flaw exists in the kernel mode layer
    (nvlddmkm.sys) handler for DxgDdiEscape that allows a
    local attacker to access arbitrary physical memory and
    gain elevated privileges. (CVE-2017-0344)

  - An out-of-bounds access error exists in the kernel mode
    layer (nvlddmkm.sys) handler for DxgDdiEscape due to
    improper validation of user-supplied array size input. A
    local attacker can exploit this to cause a denial of
    service condition or potentially to gain elevated
    privileges. (CVE-2017-0345)

  - A buffer overflow condition exists in the kernel mode
    layer (nvlddmkm.sys) handler for DxgDdiEscape due to
    improper validation of user-supplied input. A local
    attacker can exploit this to cause a denial of service
    condition or potentially to gain elevated privileges.
    (CVE-2017-0346)

  - An array-indexing error exists in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape due to improper
    validation of user-supplied input. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges. (CVE-2017-0347)

  - A NULL pointer dereference flaw exists in the kernel
    mode layer (nvlddmkm.sys) handler due to improper
    validation of user-supplied input. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges.
    (CVE-2017-0348)

  - An invalid pointer flaw exists in the kernel mode layer
    (nvlddmkm.sys) handler for DxgkDdiEscape due to improper
    validation of a user-supplied pointer before it is
    dereferenced for a write operation. A local attacker can
    exploit this to cause a denial of service condition or
    potentially to gain elevated privileges. (CVE-2017-0349)

  - A flaw exists in the kernel mode layer handler for
    DxgDdiEscape due to the driver improperly locking on
    certain conditions. A local attacker can exploit this to
    cause a denial of service condition. (CVE-2017-0353)

  - A flaw exists in the kernel mode layer handler for
    DxgkDdiEscape where a call to certain functions
    requiring lower IRQL can be made under raised IRQL. A
    local attacker can exploit this to cause a denial of
    service condition. (CVE-2017-0354)

  - A flaw exists in the kernel mode layer handler for
    DxgkDdiEscape due to accessing paged memory while
    holding a spin lock. A local attacker can exploit this
    to cause a denial of service condition.
    (CVE-2017-0355)");
  script_set_attribute(attribute:"see_also", value:"http://nvidia.custhelp.com/app/answers/detail/a_id/4462");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 377.35 / 382.05 or
later in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-0349");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nvidia:gpu_driver");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_display_drivers.nbin");
  script_require_keys("WMI/DisplayDrivers/NVIDIA", "Settings/ParanoidReport");

  exit(0);
}

include('vcf_extras_nvidia.inc');

var app_info = vcf::nvidia_gpu::get_app_info(win_local:TRUE);

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

var constraints = [
  {'min_version': '375.0', 'fixed_version': '377.35'},
  {'min_version': '381.0', 'fixed_version': '382.05'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
