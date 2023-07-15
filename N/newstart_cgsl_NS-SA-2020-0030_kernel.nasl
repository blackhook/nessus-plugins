#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2020-0030. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(138766);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2018-16871",
    "CVE-2019-8980",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-18282",
    "CVE-2019-18805",
    "CVE-2019-19045",
    "CVE-2019-19055",
    "CVE-2019-19077",
    "CVE-2019-19532",
    "CVE-2019-19534",
    "CVE-2019-19768",
    "CVE-2020-1749",
    "CVE-2020-2732",
    "CVE-2020-10711",
    "CVE-2020-11884",
    "CVE-2020-12657"
  );
  script_bugtraq_id(107120, 108547);

  script_name(english:"NewStart CGSL MAIN 6.01 : kernel Multiple Vulnerabilities (NS-SA-2020-0030)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.01, has kernel packages installed that are affected by multiple
vulnerabilities:

  - A flaw was found in the Linux kernel's NFS
    implementation, all versions 3.x and all versions 4.x up
    to 4.20. An attacker, who is able to mount an exported
    NFS filesystem, is able to trigger a null pointer
    dereference by using an invalid NFS sequence. This can
    panic the machine and deny access to the NFS server. Any
    outstanding disk writes to the NFS server will be lost.
    (CVE-2018-16871)

  - ieee802154_create in net/ieee802154/socket.c in the
    AF_IEEE802154 network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that
    unprivileged users can create a raw socket, aka
    CID-e69dbd4619e7. (CVE-2019-17053)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the
    AF_ISDN network module in the Linux kernel through 5.3.2
    does not enforce CAP_NET_RAW, which means that
    unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21. (CVE-2019-17055)

  - The flow_dissector feature in the Linux kernel 4.3
    through 5.x before 5.3.10 has a device tracking
    vulnerability, aka CID-55667441c84f. This occurs because
    the auto flowlabel of a UDP IPv6 packet relies on a
    32-bit hashrnd value as a secret, and because jhash
    (instead of siphash) is used. The hashrnd value remains
    the same starting from boot time, and can be inferred by
    an attacker. This affects net/core/flow_dissector.c and
    related code. (CVE-2019-18282)

  - An issue was discovered in net/ipv4/sysctl_net_ipv4.c in
    the Linux kernel before 5.0.11. There is a
    net/ipv4/tcp_input.c signed integer overflow in
    tcp_ack_update_rtt() when userspace writes a very large
    integer to /proc/sys/net/ipv4/tcp_min_rtt_wlen, leading
    to a denial of service or possibly unspecified other
    impact, aka CID-19fad20d15a6. (CVE-2019-18805)

  - A memory leak in the mlx5_fpga_conn_create_cq() function
    in drivers/net/ethernet/mellanox/mlx5/core/fpga/conn.c
    in the Linux kernel before 5.3.11 allows attackers to
    cause a denial of service (memory consumption) by
    triggering mlx5_vector2eqn() failures, aka
    CID-c8c2a057fdc7. (CVE-2019-19045)

  - ** DISPUTED ** A memory leak in the
    nl80211_get_ftm_responder_stats() function in
    net/wireless/nl80211.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service
    (memory consumption) by triggering nl80211hdr_put()
    failures, aka CID-1399c59fa929. NOTE: third parties
    dispute the relevance of this because it occurs on a
    code path where a successful allocation has already
    occurred. (CVE-2019-19055)

  - A memory leak in the bnxt_re_create_srq() function in
    drivers/infiniband/hw/bnxt_re/ib_verbs.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial
    of service (memory consumption) by triggering copy to
    udata failures, aka CID-4a9d46a9fe14. (CVE-2019-19077)

  - In the Linux kernel before 5.3.9, there are multiple
    out-of-bounds write bugs that can be caused by a
    malicious USB device in the Linux kernel HID drivers,
    aka CID-d9d4b1e46d95. This affects drivers/hid/hid-
    axff.c, drivers/hid/hid-dr.c, drivers/hid/hid-emsff.c,
    drivers/hid/hid-gaff.c, drivers/hid/hid-holtekff.c,
    drivers/hid/hid-lg2ff.c, drivers/hid/hid-lg3ff.c,
    drivers/hid/hid-lg4ff.c, drivers/hid/hid-lgff.c,
    drivers/hid/hid-logitech-hidpp.c, drivers/hid/hid-
    microsoft.c, drivers/hid/hid-sony.c, drivers/hid/hid-
    tmff.c, and drivers/hid/hid-zpff.c. (CVE-2019-19532)

  - In the Linux kernel before 5.3.11, there is an info-leak
    bug that can be caused by a malicious USB device in the
    drivers/net/can/usb/peak_usb/pcan_usb_core.c driver, aka
    CID-f7a1337f0d29. (CVE-2019-19534)

  - In the Linux kernel 5.4.0-rc2, there is a use-after-free
    (read) in the __blk_add_trace function in
    kernel/trace/blktrace.c (which is used to fill out a
    blk_io_trace structure and place it in a per-cpu sub-
    buffer). (CVE-2019-19768)

  - A memory leak in the kernel_read_file function in
    fs/exec.c in the Linux kernel through 4.20.11 allows
    attackers to cause a denial of service (memory
    consumption) by triggering vfs_read failures.
    (CVE-2019-8980)

  - A NULL pointer dereference flaw was found in the Linux
    kernel's SELinux subsystem in versions before 5.7. This
    flaw occurs while importing the Commercial IP Security
    Option (CIPSO) protocol's category bitmap into the
    SELinux extensible bitmap via the'
    ebitmap_netlbl_import' routine. While processing the
    CIPSO restricted bitmap tag in the
    'cipso_v4_parsetag_rbm' routine, it sets the security
    attribute to indicate that the category bitmap is
    present, even if it has not been allocated. This issue
    leads to a NULL pointer dereference issue while
    importing the same category bitmap into SELinux. This
    flaw allows a remote network user to crash the system
    kernel, resulting in a denial of service.
    (CVE-2020-10711)

  - In the Linux kernel through 5.6.7 on the s390 platform,
    code execution may occur because of a race condition, as
    demonstrated by code in enable_sacf_uaccess in
    arch/s390/lib/uaccess.c that fails to protect against a
    concurrent page table upgrade, aka CID-3f777e19d171. A
    crash could also occur. (CVE-2020-11884)

  - An issue was discovered in the Linux kernel before
    5.6.5. There is a use-after-free in block/bfq-iosched.c
    related to bfq_idle_slice_timer_body. (CVE-2020-12657)

  - A flaw was discovered in the way that the KVM hypervisor
    handled instruction emulation for an L2 guest when
    nested virtualisation is enabled. Under some
    circumstances, an L2 guest may trick the L0 guest into
    accessing sensitive L1 resources that should be
    inaccessible to the L2 guest. (CVE-2020-2732)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2020-0030");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-18805");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 6.01")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.01');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 6.01": [
    "bpftool-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "bpftool-debuginfo-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-abi-whitelists-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-core-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-cross-headers-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-core-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-debuginfo-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-devel-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-modules-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-modules-extra-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debug-modules-internal-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debuginfo-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-debuginfo-common-x86_64-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-devel-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-headers-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-ipaclones-internal-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-modules-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-modules-extra-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-modules-internal-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-selftests-internal-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-sign-keys-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-tools-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-tools-debuginfo-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-tools-libs-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "kernel-tools-libs-devel-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "perf-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "perf-debuginfo-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "python3-perf-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b",
    "python3-perf-debuginfo-4.18.0-147.8.1.el8_1.cgslv6_1.4.110.g7726f271b"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
