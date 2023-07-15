##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0078. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147318);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-9458",
    "CVE-2019-15925",
    "CVE-2019-18808",
    "CVE-2019-19046",
    "CVE-2019-19319",
    "CVE-2019-19332",
    "CVE-2019-19524",
    "CVE-2019-19537",
    "CVE-2019-19543",
    "CVE-2019-20636",
    "CVE-2020-8647",
    "CVE-2020-8648",
    "CVE-2020-8649",
    "CVE-2020-10732",
    "CVE-2020-10751",
    "CVE-2020-11565",
    "CVE-2020-11668",
    "CVE-2020-12351",
    "CVE-2020-12352",
    "CVE-2020-12659",
    "CVE-2020-12770",
    "CVE-2020-14331",
    "CVE-2020-14386"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : kernel Multiple Vulnerabilities (NS-SA-2021-0078)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has kernel packages installed that are affected by multiple
vulnerabilities:

  - An issue was discovered in the Linux kernel before 5.2.3. An out of bounds access exists in the function
    hclge_tm_schd_mode_vnet_base_cfg in the file drivers/net/ethernet/hisilicon/hns3/hns3pf/hclge_tm.c.
    (CVE-2019-15925)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - ** DISPUTED ** A memory leak in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c
    in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by
    triggering ida_simple_get() failure, aka CID-4aa7afb0ee20. NOTE: third parties dispute the relevance of
    this because an attacker cannot realistically control this failure at probe time. (CVE-2019-19046)

  - In the Linux kernel before 5.2, a setxattr operation, after a mount of a crafted ext4 image, can cause a
    slab-out-of-bounds write access because of an ext4_xattr_set_entry use-after-free in fs/ext4/xattr.c when
    a large old_size value is used in a memset call, aka CID-345c0dbf3a30. (CVE-2019-19319)

  - An out-of-bounds memory write issue was found in the Linux Kernel, version 3.13 through 5.4, in the way
    the Linux kernel's KVM hypervisor handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of service. (CVE-2019-19332)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - In the Linux kernel before 5.1.6, there is a use-after-free in serial_ir_init_module() in
    drivers/media/rc/serial_ir.c. (CVE-2019-19543)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - In the Android kernel in the video driver there is a use after free due to a race condition. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9458)

  - A flaw was found in the Linux kernel's implementation of Userspace core dumps. This flaw allows an
    attacker with a local account to crash a trivial program and exfiltrate private kernel data.
    (CVE-2020-10732)

  - A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it
    incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly
    only validate the first netlink message in the skb and allow or deny the rest of the messages within the
    skb with the granted permission without further processing. (CVE-2020-10751)

  - ** DISPUTED ** An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c
    has a stack-based out-of-bounds write because an empty nodelist is mishandled during mount option parsing,
    aka CID-aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability
    because the issue is a bug in parsing mount options which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not already held.. (CVE-2020-11565)

  - In the Linux kernel before 5.6.1, drivers/media/usb/gspca/xirlink_cit.c (aka the Xirlink camera USB
    driver) mishandles invalid descriptors, aka CID-a246b4d54770. (CVE-2020-11668)

  - Improper input validation in BlueZ may allow an unauthenticated user to potentially enable escalation of
    privilege via adjacent access. (CVE-2020-12351)

  - Improper access control in BlueZ may allow an unauthenticated user to potentially enable information
    disclosure via adjacent access. (CVE-2020-12352)

  - An issue was discovered in the Linux kernel before 5.6.7. xdp_umem_reg in net/xdp/xdp_umem.c has an out-
    of-bounds write (by a user with the CAP_NET_ADMIN capability) because of a lack of headroom validation.
    (CVE-2020-12659)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - A flaw was found in the Linux kernels implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - A flaw was found in the Linux kernel before 5.9-rc4. Memory corruption can be exploited to gain root
    privileges from unprivileged processes. The highest threat from this vulnerability is to data
    confidentiality and integrity. (CVE-2020-14386)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c. (CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the n_tty_receive_buf_common
    function in drivers/tty/n_tty.c. (CVE-2020-8648)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region
    function in drivers/video/console/vgacon.c. (CVE-2020-8649)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0078");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14386");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-12351");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/21");
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

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'bpftool-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'bpftool-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-abi-whitelists-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-core-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-cross-headers-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-core-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-devel-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-modules-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debug-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-debuginfo-common-x86_64-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-devel-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-headers-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-ipaclones-internal-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-modules-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-modules-extra-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-modules-internal-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-selftests-internal-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-sign-keys-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-tools-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-tools-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-tools-libs-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'kernel-tools-libs-devel-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'perf-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'python3-perf-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f',
    'python3-perf-debuginfo-4.18.0-193.14.2.el8_2.cgslv6_2.12.326.ga88c06e1f'
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
