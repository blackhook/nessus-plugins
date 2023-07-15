#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106167);
  script_version("3.65");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-1000407",
    "CVE-2017-12190",
    "CVE-2017-12193",
    "CVE-2017-15868",
    "CVE-2017-16939",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17450",
    "CVE-2017-17558",
    "CVE-2017-17805",
    "CVE-2017-17806",
    "CVE-2017-17807",
    "CVE-2017-7542",
    "CVE-2017-8824"
  );

  script_name(english:"EulerOS 2.0 SP2 : kernel (EulerOS-SA-2018-1026)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The XFRM dump policy implementation in
    net/xfrm/xfrm_user.c in the Linux kernel before 4.13.11
    allows local users to gain privileges or cause a denial
    of service (use-after-free) via a crafted SO_RCVBUF
    setsockopt system call in conjunction with
    XFRM_MSG_GETPOLICY Netlink messages.(CVE-2017-16939)

  - The bio_map_user_iov and bio_unmap_user functions in
    block/bio.c in the Linux kernel before 4.13.8 do
    unbalanced refcounting when a SCSI I/O vector has small
    consecutive buffers belonging to the same page. The
    bio_add_pc_page function merges them into one, but the
    page reference is never dropped. This causes a memory
    leak and possible system lockup (exploitable against
    the host OS by a guest OS user, if a SCSI disk is
    passed through to a virtual machine) due to an
    out-of-memory condition.(CVE-2017-12190)

  - The assoc_array_insert_into_terminal_node function in
    lib/assoc_array.c in the Linux kernel before 4.13.11
    mishandles node splitting, which allows local users to
    cause a denial of service (NULL pointer dereference and
    panic) via a crafted application, as demonstrated by
    the keyring key type, and key addition and link
    creation operations.(CVE-2017-12193)

  - The ip6_find_1stfragopt function in
    net/ipv6/output_core.c in the Linux kernel through
    4.12.3 allows local users to cause a denial of service
    (integer overflow and infinite loop) by leveraging the
    ability to open a raw socket.(CVE-2017-7542)

  - The bnep_add_connection function in
    net/bluetooth/bnep/core.c in the Linux kernel before
    3.19 does not ensure that an l2cap socket is available,
    which allows local users to gain privileges via a
    crafted application.(CVE-2017-15868)

  - The dccp_disconnect function in net/dccp/proto.c in the
    Linux kernel through 4.14.3 allows local users to gain
    privileges or cause a denial of service
    (use-after-free) via an AF_UNSPEC connect system call
    during the DCCP_LISTEN state.(CVE-2017-8824)

  - net/netfilter/nfnetlink_cthelper.c in the Linux kernel
    through 4.14.4 does not require the CAP_NET_ADMIN
    capability for new, get, and del operations, which
    allows local users to bypass intended access
    restrictions because the nfnl_cthelper_list data
    structure is shared across all net
    namespaces.(CVE-2017-17448)

  - The __netlink_deliver_tap_skb function in
    net/netlink/af_netlink.c in the Linux kernel through
    4.14.4, when CONFIG_NLMON is enabled, does not restrict
    observations of Netlink messages to a single net
    namespace, which allows local users to obtain sensitive
    information by leveraging the CAP_NET_ADMIN capability
    to sniff an nlmon interface for all Netlink activity on
    the system.(CVE-2017-17449)

  - net/netfilter/xt_osf.c in the Linux kernel through
    4.14.4 does not require the CAP_NET_ADMIN capability
    for add_callback and remove_callback operations, which
    allows local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all net namespaces.(CVE-2017-17450)

  - The usb_destroy_configuration function in
    drivers/usb/core/config.c in the USB core subsystem in
    the Linux kernel through 4.14.5 does not consider the
    maximum number of configurations and interfaces before
    attempting to release resources, which allows local
    users to cause a denial of service (out-of-bounds write
    access) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-17558)

  - The Salsa20 encryption algorithm in the Linux kernel
    before 4.14.8 does not correctly handle zero-length
    inputs, allowing a local attacker able to use the
    AF_ALG-based skcipher interface
    (CONFIG_CRYPTO_USER_API_SKCIPHER) to cause a denial of
    service (uninitialized-memory free and kernel crash) or
    have unspecified other impact by executing a crafted
    sequence of system calls that use the blkcipher_walk
    API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 were
    vulnerable.(CVE-2017-17805)

  - The HMAC implementation (crypto/hmac.c) in the Linux
    kernel before 4.14.8 does not validate that the
    underlying cryptographic hash algorithm is unkeyed,
    allowing a local attacker able to use the AF_ALG-based
    hash interface (CONFIG_CRYPTO_USER_API_HASH) and the
    SHA-3 hash algorithm (CONFIG_CRYPTO_SHA3) to cause a
    kernel stack buffer overflow by executing a crafted
    sequence of system calls that encounter a missing SHA-3
    initialization.(CVE-2017-17806)

  - he KEYS subsystem in the Linux kernel before 4.14.6
    omitted an access-control check when adding a key to
    the current task's 'default request-key keyring' via
    the request_key() system call, allowing a local user to
    use a sequence of crafted system calls to add keys to a
    keyring with only Search permission (not Write
    permission) to that keyring, related to
    construct_get_dest_keyring() in
    security/keys/request_key.c.(CVE-2017-17807)

  - The Linux Kernel 2.6.32 and later are affected by a
    denial of service, by flooding the diagnostic port 0x80
    an exception can be triggered leading to a kernel
    panic.(CVE-2017-1000407)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1026
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eab3a3ba");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/19");

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

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["kernel-3.10.0-327.59.59.46.h49",
        "kernel-debug-3.10.0-327.59.59.46.h49",
        "kernel-debug-devel-3.10.0-327.59.59.46.h49",
        "kernel-debuginfo-3.10.0-327.59.59.46.h49",
        "kernel-debuginfo-common-x86_64-3.10.0-327.59.59.46.h49",
        "kernel-devel-3.10.0-327.59.59.46.h49",
        "kernel-headers-3.10.0-327.59.59.46.h49",
        "kernel-tools-3.10.0-327.59.59.46.h49",
        "kernel-tools-libs-3.10.0-327.59.59.46.h49",
        "perf-3.10.0-327.59.59.46.h49",
        "python-perf-3.10.0-327.59.59.46.h49"];

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
