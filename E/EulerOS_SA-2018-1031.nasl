#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106406);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-3695",
    "CVE-2016-7915",
    "CVE-2017-0861",
    "CVE-2017-1000407",
    "CVE-2017-13215",
    "CVE-2017-15868",
    "CVE-2017-16939",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17450",
    "CVE-2017-17558",
    "CVE-2017-17805",
    "CVE-2017-17806",
    "CVE-2017-17807",
    "CVE-2017-18017",
    "CVE-2017-8824",
    "CVE-2018-5332",
    "CVE-2018-5333",
    "CVE-2018-5344"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2018-1031)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The hid_input_field function in drivers/hid/hid-core.c
    in the Linux kernel before 4.6 allows physically
    proximate attackers to obtain sensitive information
    from kernel memory or cause a denial of service
    (out-of-bounds read) by connecting a device, as
    demonstrated by a Logitech DJ receiver.(CVE-2016-7915)

  - In the Linux kernel through 4.14.13,
    drivers/block/loop.c mishandles lo_release
    serialization, which allows attackers to cause a denial
    of service (__lock_acquire use-after-free) or possibly
    have unspecified other impact.(CVE-2018-5344)

  - In the Linux kernel through 4.14.13, the
    rds_cmsg_atomic() function in 'net/rds/rdma.c'
    mishandles cases where page pinning fails or an invalid
    address is supplied by a user. This can lead to a NULL
    pointer dereference in rds_atomic_free_op() and thus to
    a system panic.(CVE-2018-5333)

  - In the Linux kernel through 4.14.13, the
    rds_message_alloc_sgs() function does not validate a
    value that is used during DMA page allocation, leading
    to a heap-based out-of-bounds write (related to the
    rds_rdma_extra_size() function in 'net/rds/rdma.c') and
    thus to a system panic. Due to the nature of the flaw,
    privilege escalation cannot be fully ruled out,
    although we believe it is unlikely.(CVE-2018-5332)

  - A flaw was found in the upstream kernel Skcipher
    component. This vulnerability affects the
    skcipher_recvmsg function of the component Skcipher.
    The manipulation with an unknown input leads to a
    privilege escalation vulnerability.(CVE-2017-13215)

  - The tcpmss_mangle_packet function in
    net/netfilter/xt_TCPMSS.c in the Linux kernel before
    4.11, and 4.9.x before 4.9.36, allows remote attackers
    to cause a denial of service (use-after-free and memory
    corruption) or possibly have unspecified other impact
    by leveraging the presence of xt_TCPMSS in an iptables
    action.(CVE-2017-18017)

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

  - The XFRM dump policy implementation in
    net/xfrm/xfrm_user.c in the Linux kernel before 4.13.11
    allows local users to gain privileges or cause a denial
    of service (use-after-free) via a crafted SO_RCVBUF
    setsockopt system call in conjunction with
    XFRM_MSG_GETPOLICY Netlink messages.(CVE-2017-16939)

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

  - Use-after-free vulnerability in the snd_pcm_info
    function in the ALSA subsystem in the Linux kernel
    allows attackers to gain privileges via unspecified
    vectors.(CVE-2017-0861)

  - The usb_destroy_configuration function in
    drivers/usb/core/config.c in the USB core subsystem in
    the Linux kernel through 4.14.5 does not consider the
    maximum number of configurations and interfaces before
    attempting to release resources, which allows local
    users to cause a denial of service (out-of-bounds write
    access) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-17558)

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

  - The bnep_add_connection function in
    net/bluetooth/bnep/core.c in the Linux kernel before
    3.19 does not ensure that an l2cap socket is available,
    which allows local users to gain privileges via a
    crafted application.(CVE-2017-15868)

  - The einj_error_inject function in
    drivers/acpi/apei/einj.c in the Linux kernel allows
    local users to simulate hardware errors and
    consequently cause a denial of service by leveraging
    failure to disable APEI error injection through EINJ
    when securelevel is set.(CVE-2016-3695)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1031
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40acf6f7");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Reliable Datagram Sockets (RDS) rds_atomic_free_op NULL pointer dereference Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debug");
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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.172",
        "kernel-debug-3.10.0-229.49.1.172",
        "kernel-debuginfo-3.10.0-229.49.1.172",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.172",
        "kernel-devel-3.10.0-229.49.1.172",
        "kernel-headers-3.10.0-229.49.1.172",
        "kernel-tools-3.10.0-229.49.1.172",
        "kernel-tools-libs-3.10.0-229.49.1.172",
        "perf-3.10.0-229.49.1.172",
        "python-perf-3.10.0-229.49.1.172"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"1", reference:pkg)) flag++;

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
