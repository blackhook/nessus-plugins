#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94576);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/05");

  script_cve_id(
    "CVE-2016-7381",
    "CVE-2016-7382",
    "CVE-2016-7383",
    "CVE-2016-7384",
    "CVE-2016-7385",
    "CVE-2016-7386",
    "CVE-2016-7387",
    "CVE-2016-7388",
    "CVE-2016-7390",
    "CVE-2016-7391",
    "CVE-2016-8805",
    "CVE-2016-8806",
    "CVE-2016-8807",
    "CVE-2016-8808",
    "CVE-2016-8809",
    "CVE-2016-8810",
    "CVE-2016-8811",
    "CVE-2016-8812"
  );
  script_bugtraq_id(
    93981,
    93982,
    93983,
    93984,
    93985,
    93986,
    93987,
    93988,
    93990,
    93992,
    93997,
    93999,
    94001,
    94002
  );

  script_name(english:"NVIDIA Windows GPU Display Driver 340.x / 341.x / 342.x < 342.00 / 375.x < 375.63 Multiple Vulnerabilities");
  script_summary(english:"Checks the driver version.");

  script_set_attribute(attribute:"synopsis", value:
"A display driver installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of the NVIDIA GPU display driver installed on the remote
Windows host is 340.x, 341.x, or 342.x prior to 342.00, or 375.x prior
to 375.63. It is, therefore, affected by multiple vulnerabilities :

  - An array-indexing error exists in nvlddmkm.sys due to
    improper validation of input. A local attacker can
    exploit this to cause a denial of service condition or
    the execution of arbitrary code with elevated
    privileges. (CVE-2016-7381)

  - A flaw exists in nvlddmkm.sys due to missing permission
    checks. A local attacker can exploit this to disclose
    arbitrary memory contents and gain elevated privileges.
    (CVE-2016-7382)

  - A flaw exists in nvlddmkm.sys when handling memory
    mapping that allows a local attacker to cause a denial
    of service condition or the execution of arbitrary code
    with elevated privileges. (CVE-2016-7383)

  - A flaw exists in nvlddmkm.sys when handling
    UVMLiteController device IO control input and output
    lengths. A local attacker can exploit this to execute
    arbitrary code with elevated privileges. (CVE-2016-7384)

  - An untrusted pointer dereference flaw exists in
    nvlddmkm.sys when handling DxgDdiEscape ID 0x700010d. A
    local attacker can exploit this to cause a denial of
    service condition or the execution of arbitrary code
    with elevated privileges. (CVE-2016-7385)

  - A flaw exists in nvlddmkm.sys when handling DxgDdiEscape
    ID 0x70000d4 that allows a local attacker to disclose
    uninitialized memory contents. (CVE-2016-7386)

  - A flaw exists in nvlddmkm.sys when handling DxgDdiEscape
    ID 0x600000d that allows a local attacker to cause a
    denial of service condition or the execution of
    arbitrary code with elevated privileges. (CVE-2016-7387)

  - A NULL pointer dereference flaw exists in nvlddmkm.sys
    that allows a local attacker to cause a denial of
    service condition or the execution of arbitrary code
    with elevated privileges in certain unsafe
    configurations. (CVE-2016-7388)

  - An array-indexing error exists in nvlddmkm.sys when
    handling DxgDdiEscape ID 0x7000194 that allows a local
    attacker to cause a denial of service condition or the
    execution of arbitrary code with elevated privileges.
    (CVE-2016-7390)

  - A flaw exists in nvlddmkm.sys when handling DxgDdiEscape
    ID 0x100010b that allows a local attacker to cause a
    denial of service condition or the execution of
    arbitrary code with elevated privileges. (CVE-2016-7391)

  - A flaw exists in nvlddmkm.sys when handling DxgDdiEscape
    ID 0x7000014 that allows a local attacker to cause a
    denial of service condition or the execution of
    arbitrary code with elevated privileges. (CVE-2016-8805)

  - An untrusted pointer dereference flaw exists in
    nvlddmkm.sys when handling DxgDdiEscape ID 0x5000027
    that allows a local attacker to cause a denial of
    service condition or the execution of arbitrary code
    with elevated privileges. (CVE-2016-8806)

  - A stack-based buffer overflow condition exists in
    nvlddmkm.sys when handling DxgDdiEscape ID 0x10000e9
    that allows a local attacker to cause a denial of
    service condition or the execution of arbitrary code
    with elevated privileges. (CVE-2016-8807)

  - A buffer overflow condition exists in nvlddmkm.sys when
    handling DxgDdiEscape ID 0x70000d that allows a local
    attacker to cause a denial of service condition or the
    execution of arbitrary code with elevated privileges.
    (CVE-2016-8808)

  - A buffer overflow condition exists in nvlddmkm.sys when
    handling DxgDdiEscape ID 0x70001b2 that allows a local
    attacker to cause a denial of service condition or the
    execution of arbitrary code with elevated privileges.
    (CVE-2016-8809)

  - A buffer overflow condition exists in nvlddmkm.sys when
    handling DxgDdiEscape ID 0x100009a that allows a local
    attacker to cause a denial of service condition or the
    execution of arbitrary code with elevated privileges.
    (CVE-2016-8810)

  - A flaw exists in nvlddmkm.sys driver when handling
    DxgDdiEscape ID 0x7000170 that allows a local attacker
    to cause a denial of service condition or the execution
    of arbitrary code with elevated privileges.
    (CVE-2016-8811)

  - A stack-based overflow condition exists in
    nvstreamkms.sys when handling executable paths. A local
    attacker can exploit this to execute arbitrary code with
    elevated privileges. Note that this vulnerability only
    affects systems that also have GeForce Experience
    software installed. (CVE-2016-8812)");
  script_set_attribute(attribute:"see_also", value:"https://nvidia.custhelp.com/app/answers/detail/a_id/4247");
  script_set_attribute(attribute:"solution", value:
"Upgrade the NVIDIA graphics driver to version 342.00 / 375.63 or
later in accordance with the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-7381");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/11/04");

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
  {'min_version': '340.0', 'fixed_version': '342.00'},
  {'min_version': '375.0', 'fixed_version': '375.63'}
];

vcf::nvidia_gpu::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_NOTE
);
