#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164566);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2019-19527",
    "CVE-2020-10757",
    "CVE-2020-12653",
    "CVE-2020-12654"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.18.0.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.18.0.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.18.0.5 advisory.

  - In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/hid/usbhid/hiddev.c driver, aka CID-9c09b214f30e. (CVE-2019-19527)

  - A flaw was found in the Linux Kernel in versions after 4.5-rc1 in the way mremap handled DAX Huge Pages.
    This flaw allows a local attacker with access to a DAX enabled storage to escalate their privileges on the
    system. (CVE-2020-10757)

  - An issue was found in Linux kernel before 5.5.4. The mwifiex_cmd_append_vsie_tlv() function in
    drivers/net/wireless/marvell/mwifiex/scan.c allows local users to gain privileges or cause a denial of
    service because of an incorrect memcpy and buffer overflow, aka CID-b70261a288ea. (CVE-2020-12653)

  - An issue was found in Linux kernel before 5.5.4. mwifiex_ret_wmm_get_status() in
    drivers/net/wireless/marvell/mwifiex/wmm.c allows a remote AP to trigger a heap-based buffer overflow
    because of an incorrect memcpy, aka CID-3a9b153c5591. (CVE-2020-12654)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.18.0.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f35325f8");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19527");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12653");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.18.0.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.18.0.5 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.18.0.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.18.0.5 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
