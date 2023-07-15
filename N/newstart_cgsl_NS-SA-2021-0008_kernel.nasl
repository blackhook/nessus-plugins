##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0008. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147273);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2017-14489",
    "CVE-2017-18270",
    "CVE-2019-19527",
    "CVE-2020-10757",
    "CVE-2020-12653",
    "CVE-2020-12654",
    "CVE-2020-12888"
  );
  script_bugtraq_id(101011, 104254);

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2021-0008)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - The iscsi_if_rx function in drivers/scsi/scsi_transport_iscsi.c in the Linux kernel through 4.13.2 allows
    local users to cause a denial of service (panic) by leveraging incorrect length validation.
    (CVE-2017-14489)

  - In the Linux kernel before 4.13.5, a local user could create keyrings for other users via keyctl commands,
    setting unwanted defaults or causing a denial of service. (CVE-2017-18270)

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

  - The VFIO PCI driver in the Linux kernel through 5.6.13 mishandles attempts to access disabled memory
    space. (CVE-2020-12888)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0008");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19527");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12653");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL CORE 5.04" &&
    release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.04 / NewStart CGSL MAIN 5.04');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL CORE 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.51.865.gdf848d6.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.49.889.g15c87cd'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
