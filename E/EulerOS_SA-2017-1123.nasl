#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101853);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2014-9940",
    "CVE-2016-10208",
    "CVE-2017-5986",
    "CVE-2017-6353",
    "CVE-2017-7487",
    "CVE-2017-7495",
    "CVE-2017-7645",
    "CVE-2017-8890",
    "CVE-2017-8924",
    "CVE-2017-9074",
    "CVE-2017-9075",
    "CVE-2017-9077",
    "CVE-2017-9242"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2017-1123)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The regulator_ena_gpio_free function in
    drivers/regulator/core.c in the Linux kernel allows
    local users to gain privileges or cause a denial of
    service (use-after-free) via a crafted
    application.i1/4^CVE-2014-9940i1/4%0

  - Race condition in the sctp_wait_for_sndbuf function in
    net/sctp/socket.c in the Linux kernel before 4.9.11
    allows local users to cause a denial of service
    (assertion failure and panic) via a multithreaded
    application that peels off an association in a certain
    buffer-full state.i1/4^CVE-2017-5986i1/4%0

  - net/sctp/socket.c in the Linux kernel through 4.10.1
    does not properly restrict association peel-off
    operations during certain wait states, which allows
    local users to cause a denial of service (invalid
    unlock and double free) via a multithreaded
    application. NOTE: this vulnerability exists because of
    an incorrect fix for CVE-2017-5986.i1/4^CVE-2017-6353i1/4%0

  - The ipxitf_ioctl function in net/ipx/af_ipx.c in the
    Linux kernel through 4.11.1 mishandles reference
    counts, which allows local users to cause a denial of
    service (use-after-free) or possibly have unspecified
    other impact via a failed SIOCGIFADDR ioctl call for an
    IPX interface.i1/4^CVE-2017-7487i1/4%0

  - fs/ext4/inode.c in the Linux kernel before 4.6.2, when
    ext4 data=ordered mode is used, mishandles a
    needs-flushing-before-commit list, which allows local
    users to obtain sensitive information from other users'
    files in opportunistic circumstances by waiting for a
    hardware reset, creating a new file, making write
    system calls, and reading this file.i1/4^CVE-2017-7495i1/4%0

  - The NFSv2/NFSv3 server in the nfsd subsystem in the
    Linux kernel through 4.10.11 allows remote attackers to
    cause a denial of service (system crash) via a long RPC
    reply, related to net/sunrpc/svc.c, fs/nfsd/nfs3xdr.c,
    and fs/nfsd/nfsxdr.c.i1/4^CVE-2017-7645i1/4%0

  - The inet_csk_clone_lock function in
    net/ipv4/inet_connection_sock.c in the Linux kernel
    through 4.10.15 allows attackers to cause a denial of
    service (double free) or possibly have unspecified
    other impact by leveraging use of the accept system
    call.i1/4^CVE-2017-8890i1/4%0

  - The edge_bulk_in_callback function in
    drivers/usb/serial/io_ti.c in the Linux kernel before
    4.10.4 allows local users to obtain sensitive
    information (in the dmesg ringbuffer and syslog) from
    uninitialized kernel memory by using a crafted USB
    device (posing as an io_ti USB serial device) to
    trigger an integer underflow.i1/4^CVE-2017-8924i1/4%0

  - The IPv6 fragmentation implementation in the Linux
    kernel through 4.11.1 does not consider that the
    nexthdr field may be associated with an invalid option,
    which allows local users to cause a denial of service
    (out-of-bounds read and BUG) or possibly have
    unspecified other impact via crafted socket and send
    system calls.i1/4^CVE-2017-9074i1/4%0

  - The sctp_v6_create_accept_sk function in
    net/sctp/ipv6.c in the Linux kernel through 4.11.1
    mishandles inheritance, which allows local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted system calls, a related issue
    to CVE-2017-8890.i1/4^CVE-2017-9075i1/4%0

  - The tcp_v6_syn_recv_sock function in
    net/ipv6/tcp_ipv6.c in the Linux kernel through 4.11.1
    mishandles inheritance, which allows local users to
    cause a denial of service or possibly have unspecified
    other impact via crafted system calls, a related issue
    to CVE-2017-8890.i1/4^CVE-2017-9077i1/4%0

  - The __ip6_append_data function in net/ipv6/ip6_output.c
    in the Linux kernel through 4.11.3 is too late in
    checking whether an overwrite of an skb data structure
    may occur, which allows local users to cause a denial
    of service (system crash) via crafted system
    calls.i1/4^CVE-2017-9242i1/4%0

  - The ext4_fill_super function in fs/ext4/super.c in the
    Linux kernel through 4.9.8 does not properly validate
    meta block groups, which allows physically proximate
    attackers to cause a denial of service (out-of-bounds
    read and system crash) via a crafted ext4
    image.i1/4^CVE-2016-10208i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1123
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9421159a");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-327.53.58.73.h2",
        "kernel-debug-3.10.0-327.53.58.73.h2",
        "kernel-debug-devel-3.10.0-327.53.58.73.h2",
        "kernel-debuginfo-3.10.0-327.53.58.73.h2",
        "kernel-debuginfo-common-x86_64-3.10.0-327.53.58.73.h2",
        "kernel-devel-3.10.0-327.53.58.73.h2",
        "kernel-headers-3.10.0-327.53.58.73.h2",
        "kernel-tools-3.10.0-327.53.58.73.h2",
        "kernel-tools-libs-3.10.0-327.53.58.73.h2",
        "perf-3.10.0-327.53.58.73.h2",
        "python-perf-3.10.0-327.53.58.73.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
