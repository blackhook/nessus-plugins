##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2022-0075. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160761);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2017-2647",
    "CVE-2017-12192",
    "CVE-2017-1000371",
    "CVE-2018-12207",
    "CVE-2019-0154",
    "CVE-2019-0155",
    "CVE-2019-3900",
    "CVE-2019-11135",
    "CVE-2019-11487",
    "CVE-2019-14821",
    "CVE-2019-17055",
    "CVE-2019-17133",
    "CVE-2019-17666",
    "CVE-2020-10711",
    "CVE-2020-29661",
    "CVE-2021-20265",
    "CVE-2021-27364",
    "CVE-2021-27365"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"NewStart CGSL MAIN 4.06 : kernel Multiple Vulnerabilities (NS-SA-2022-0075)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.06, has kernel packages installed that are affected by multiple
vulnerabilities:

  - The offset2lib patch as used by the Linux Kernel contains a vulnerability, if RLIMIT_STACK is set to
    RLIM_INFINITY and 1 Gigabyte of memory is allocated (the maximum under the 1/4 restriction) then the stack
    will be grown down to 0x80000000, and as the PIE binary is mapped above 0x80000000 the minimum distance
    between the end of the PIE binary's read-write segment and the start of the stack becomes small enough
    that the stack guard page can be jumped over by an attacker. This affects Linux Kernel version 4.11.5.
    This is a different issue than CVE-2017-1000370 and CVE-2017-1000365. This issue appears to be limited to
    i386 based systems. (CVE-2017-1000371)

  - The keyctl_read_key function in security/keys/keyctl.c in the Key Management subcomponent in the Linux
    kernel before 4.13.5 does not properly consider that a key may be possessed but negatively instantiated,
    which allows local users to cause a denial of service (OOPS and system crash) via a crafted KEYCTL_READ
    operation. (CVE-2017-12192)

  - The KEYS subsystem in the Linux kernel before 3.18 allows local users to gain privileges or cause a denial
    of service (NULL pointer dereference and system crash) via vectors involving a NULL value for a certain
    match field, related to the keyring_search_iterator function in keyring.c. (CVE-2017-2647)

  - Improper invalidation for page table updates by a virtual guest operating system for multiple Intel(R)
    Processors may allow an authenticated user to potentially enable denial of service of the host system via
    local access. (CVE-2018-12207)

  - Insufficient access control in subsystem for Intel (R) processor graphics in 6th, 7th, 8th and 9th
    Generation Intel(R) Core(TM) Processor Families; Intel(R) Pentium(R) Processor J, N, Silver and Gold
    Series; Intel(R) Celeron(R) Processor J, N, G3900 and G4900 Series; Intel(R) Atom(R) Processor A and E3900
    Series; Intel(R) Xeon(R) Processor E3-1500 v5 and v6 and E-2100 Processor Families may allow an
    authenticated user to potentially enable denial of service via local access. (CVE-2019-0154)

  - Insufficient access control in a subsystem for Intel (R) processor graphics in 6th, 7th, 8th and 9th
    Generation Intel(R) Core(TM) Processor Families; Intel(R) Pentium(R) Processor J, N, Silver and Gold
    Series; Intel(R) Celeron(R) Processor J, N, G3900 and G4900 Series; Intel(R) Atom(R) Processor A and E3900
    Series; Intel(R) Xeon(R) Processor E3-1500 v5 and v6, E-2100 and E-2200 Processor Families; Intel(R)
    Graphics Driver for Windows before 26.20.100.6813 (DCH) or 26.20.100.6812 and before 21.20.x.5077
    (aka15.45.5077), i915 Linux Driver for Intel(R) Processor Graphics before versions 5.4-rc7, 5.3.11,
    4.19.84, 4.14.154, 4.9.201, 4.4.201 may allow an authenticated user to potentially enable escalation of
    privilege via local access. (CVE-2019-0155)

  - TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11135)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - An out-of-bounds access issue was found in the Linux kernel, all versions through 5.3, in the way Linux
    kernel's KVM hypervisor implements the Coalesced MMIO write operation. It operates on an MMIO ring buffer
    'struct kvm_coalesced_mmio' object, wherein write indices 'ring->first' and 'ring->last' value could be
    supplied by a host user-space process. An unprivileged host user or process with access to '/dev/kvm'
    device could use this flaw to crash the host kernel, resulting in a denial of service or potentially
    escalating privileges on the system. (CVE-2019-14821)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21. (CVE-2019-17055)

  - In the Linux kernel through 5.3.2, cfg80211_mgd_wext_giwessid in net/wireless/wext-sme.c does not reject a
    long SSID IE, leading to a Buffer Overflow. (CVE-2019-17133)

  - rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a
    certain upper-bound check, leading to a buffer overflow. (CVE-2019-17666)

  - An infinite loop issue was found in the vhost_net kernel module in Linux Kernel up to and including
    v5.1-rc6, while handling incoming packets in handle_rx(). It could occur if one end sends packets faster
    than the other end can process them. A guest user, maybe remote one, could use this flaw to stall the
    vhost_net kernel thread, resulting in a DoS scenario. (CVE-2019-3900)

  - A NULL pointer dereference flaw was found in the Linux kernel's SELinux subsystem in versions before 5.7.
    This flaw occurs while importing the Commercial IP Security Option (CIPSO) protocol's category bitmap into
    the SELinux extensible bitmap via the' ebitmap_netlbl_import' routine. While processing the CIPSO
    restricted bitmap tag in the 'cipso_v4_parsetag_rbm' routine, it sets the security attribute to indicate
    that the category bitmap is present, even if it has not been allocated. This issue leads to a NULL pointer
    dereference issue while importing the same category bitmap into SELinux. This flaw allows a remote network
    user to crash the system kernel, resulting in a denial of service. (CVE-2020-10711)

  - A locking issue was discovered in the tty subsystem of the Linux kernel through 5.9.13.
    drivers/tty/tty_jobctrl.c allows a use-after-free attack against TIOCSPGRP, aka CID-54ffccbf053b.
    (CVE-2020-29661)

  - A flaw was found in the way memory resources were freed in the unix_stream_recvmsg function in the Linux
    kernel when a signal was pending. This flaw allows an unprivileged local user to crash the system by
    exhausting available memory. The highest threat from this vulnerability is to system availability.
    (CVE-2021-20265)

  - An issue was discovered in the Linux kernel through 5.11.3. drivers/scsi/scsi_transport_iscsi.c is
    adversely affected by the ability of an unprivileged user to craft Netlink messages. (CVE-2021-27364)

  - An issue was discovered in the Linux kernel through 5.11.3. Certain iSCSI data structures do not have
    appropriate length constraints or checks, and can exceed the PAGE_SIZE value. An unprivileged user can
    send a Netlink message that is associated with iSCSI, and has a length up to the maximum length of a
    Netlink message. (CVE-2021-27365)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2022-0075");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-1000371");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-12192");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2017-2647");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2018-12207");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-0154");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-0155");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-11135");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-11487");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-14821");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-17055");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-17133");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-17666");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2019-3900");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-10711");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2020-29661");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-20265");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-27364");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2021-27365");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL kernel packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-17133");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 4.06")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.06');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 4.06': [
    'kernel-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-abi-whitelists-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-debug-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-debug-debuginfo-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-debug-devel-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-debuginfo-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-debuginfo-common-x86_64-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-devel-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-firmware-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'kernel-headers-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'perf-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'perf-debuginfo-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'python-perf-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39',
    'python-perf-debuginfo-2.6.32-754.29.1.el6.cgslv4_6.0.41.geafdc39'
  ]
};
var pkg_list = pkgs[release];

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel');
}
