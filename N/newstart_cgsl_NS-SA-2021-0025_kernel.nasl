#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0025. The text
# itself is copyright (C) ZTE, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149336);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-9458",
    "CVE-2019-15217",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18808",
    "CVE-2019-19062",
    "CVE-2019-19332",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19530",
    "CVE-2019-19534",
    "CVE-2019-19537",
    "CVE-2020-2732",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-11565",
    "CVE-2020-14331"
  );

  script_name(english:"NewStart CGSL CORE 5.04 / MAIN 5.04 : kernel Multiple Vulnerabilities (NS-SA-2021-0025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.04 / MAIN 5.04, has kernel packages installed that are affected by
multiple vulnerabilities:

  - An issue was discovered in the Linux kernel before 5.2.3. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/media/usb/zr364xx/zr364xx.c driver. (CVE-2019-15217)

  - ieee802154_create in net/ieee802154/socket.c in the AF_IEEE802154 network module in the Linux kernel
    through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket,
    aka CID-e69dbd4619e7. (CVE-2019-17053)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21. (CVE-2019-17055)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - A memory leak in the crypto_report() function in crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    crypto_report_alg() failures, aka CID-ffdde5932042. (CVE-2019-19062)

  - An out-of-bounds memory write issue was found in the Linux Kernel, version 3.13 through 5.4, in the way
    the Linux kernel's KVM hypervisor handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of service. (CVE-2019-19332)

  - In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/misc/adutux.c driver, aka CID-44efc269db79. (CVE-2019-19523)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef. (CVE-2019-19530)

  - In the Linux kernel before 5.3.11, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/net/can/usb/peak_usb/pcan_usb_core.c driver, aka CID-f7a1337f0d29. (CVE-2019-19534)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - In the Android kernel in the video driver there is a use after free due to a race condition. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9458)

  - ** DISPUTED ** An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c
    has a stack-based out-of-bounds write because an empty nodelist is mishandled during mount option parsing,
    aka CID-aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability
    because the issue is a bug in parsing mount options which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not already held.. (CVE-2020-11565)

  - A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - A flaw was discovered in the way that the KVM hypervisor handled instruction emulation for an L2 guest
    when nested virtualisation is enabled. Under some circumstances, an L2 guest may trick the L0 guest into
    accessing sensitive L1 resources that should be inaccessible to the L2 guest. (CVE-2020-2732)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c. (CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region
    function in drivers/video/console/vgacon.c. (CVE-2020-8649)

  - An issue was discovered in the Linux kernel 3.16 through 5.5.6. set_fdc in drivers/block/floppy.c leads to
    a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it,
    aka CID-2e90ca68b0d2. (CVE-2020-9383)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0025");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14331");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-9383");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/07");

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
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-core-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-debug-core-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-debug-modules-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-modules-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.54.913.g2925469.lite'
  ],
  'CGSL MAIN 5.04': [
    'kernel-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-abi-whitelists-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-debug-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-debug-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-debug-devel-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-debuginfo-common-x86_64-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-devel-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-headers-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-sign-keys-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-tools-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-tools-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-tools-libs-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'kernel-tools-libs-devel-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'perf-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'python-perf-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff',
    'python-perf-debuginfo-3.10.0-693.21.1.el7.cgslv5_4.52.955.gcf9f7ff'
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
