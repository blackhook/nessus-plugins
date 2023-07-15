#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124824);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-16533",
    "CVE-2017-16534",
    "CVE-2017-16535",
    "CVE-2017-16536",
    "CVE-2017-16537",
    "CVE-2017-16538",
    "CVE-2017-16643",
    "CVE-2017-16644",
    "CVE-2017-16645",
    "CVE-2017-16649",
    "CVE-2017-16650",
    "CVE-2017-16939",
    "CVE-2017-17448",
    "CVE-2017-17449",
    "CVE-2017-17450",
    "CVE-2017-17558",
    "CVE-2017-17805",
    "CVE-2017-17806",
    "CVE-2017-17807",
    "CVE-2017-18079",
    "CVE-2017-18203",
    "CVE-2017-18208"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : kernel (EulerOS-SA-2019-1501)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - The usbhid_parse function in
    drivers/hid/usbhid/hid-core.c in the Linux kernel,
    before 4.13.8, allows local users to cause a denial of
    service (out-of-bounds read and system crash) or
    possibly have unspecified other impact via a crafted
    USB device.(CVE-2017-16533)

  - The cdc_parse_cdc_header() function in
    'drivers/usb/core/message.c' in the Linux kernel,
    before 4.13.6, allows local users to cause a denial of
    service (out-of-bounds read and system crash) or
    possibly have unspecified other impact via a crafted
    USB device. Due to the nature of the flaw, privilege
    escalation cannot be fully ruled out, although we
    believe it is unlikely.(CVE-2017-16534)

  - The usb_get_bos_descriptor function in
    drivers/usb/core/config.c in the Linux kernel can allow
    a local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16535)

  - The cx231xx_usb_probe function in
    drivers/media/usb/cx231xx/cx231xx-cards.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16536)

  - The imon_probe function in drivers/media/rc/imon.c in
    the Linux kernel through 4.13.11 allows local users to
    cause a denial of service (NULL pointer dereference and
    system crash) or possibly have unspecified other impact
    via a crafted USB device.(CVE-2017-16537)

  - The drivers/media/usb/dvb-usb-v2/lmedm04.c in the Linux
    kernel, through 4.13.11, allows local users to cause a
    denial of service (general protection fault and system
    crash) or possibly have unspecified other impact via a
    crafted USB device, related to a missing warm-start
    check and incorrect attach timing
    (dm04_lme2510_frontend_attach versus
    dm04_lme2510_tuner).(CVE-2017-16538)

  - The parse_hid_report_descriptor function in
    drivers/input/tablet/gtco.c in the Linux kernel before
    4.13.11 allows local users to cause a denial of service
    (out-of-bounds read and system crash) or possibly have
    unspecified other impact via a crafted USB
    device.(CVE-2017-16643)

  - The hdpvr_probe function in
    drivers/media/usb/hdpvr/hdpvr-core.c in the Linux
    kernel through 4.13.11 allows local users to cause a
    denial of service (improper error handling and system
    crash) or possibly have unspecified other impact via a
    crafted USB device.(CVE-2017-16644)

  - The ims_pcu_get_cdc_union_desc function in
    drivers/input/misc/ims-pcu.c in the Linux kernel,
    through 4.13.11, allows local users to cause a denial
    of service (ims_pcu_parse_cdc_data out-of-bounds read
    and system crash) or possibly have unspecified other
    impact via a crafted USB device.(CVE-2017-16645)

  - The usbnet_generic_cdc_bind function in
    drivers/net/usb/cdc_ether.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (divide-by-zero error and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16649)

  - The qmi_wwan_bind function in
    drivers/net/usb/qmi_wwan.c in the Linux kernel through
    4.13.11 allows local users to cause a denial of service
    (divide-by-zero error and system crash) or possibly
    have unspecified other impact via a crafted USB
    device.(CVE-2017-16650)

  - The Linux kernel is vulerable to a use-after-free flaw
    when Transformation User configuration
    interface(CONFIG_XFRM_USER) compile-time configuration
    were enabled. This vulnerability occurs while closing a
    xfrm netlink socket in xfrm_dump_policy_done. A
    user/process could abuse this flaw to potentially
    escalate their privileges on a system.(CVE-2017-16939)

  - The net/netfilter/nfnetlink_cthelper.c function in the
    Linux kernel through 4.14.4 does not require the
    CAP_NET_ADMIN capability for new, get, and del
    operations. This allows local users to bypass intended
    access restrictions because the nfnl_cthelper_list data
    structure is shared across all net
    namespaces.(CVE-2017-17448)

  - The __netlink_deliver_tap_skb function in
    net/netlink/af_netlink.c in the Linux kernel, through
    4.14.4, does not restrict observations of Netlink
    messages to a single net namespace, when CONFIG_NLMON
    is enabled. This allows local users to obtain sensitive
    information by leveraging the CAP_NET_ADMIN capability
    to sniff an nlmon interface for all Netlink activity on
    the system.(CVE-2017-17449)

  - net/netfilter/xt_osf.c in the Linux kernel through
    4.14.4 does not require the CAP_NET_ADMIN capability
    for add_callback and remove_callback operations. This
    allows local users to bypass intended access
    restrictions because the xt_osf_fingers data structure
    is shared across all network
    namespaces.(CVE-2017-17450)

  - The usb_destroy_configuration() function, in
    'drivers/usb/core/config.c' in the USB core subsystem,
    in the Linux kernel through 4.14.5 does not consider
    the maximum number of configurations and interfaces
    before attempting to release resources. This allows
    local users to cause a denial of service, due to
    out-of-bounds write access, or possibly have
    unspecified other impact via a crafted USB device. Due
    to the nature of the flaw, privilege escalation cannot
    be fully ruled out, although we believe it is
    unlikely.(CVE-2017-17558)

  - The Salsa20 encryption algorithm in the Linux kernel,
    before 4.14.8, does not correctly handle zero-length
    inputs. This allows a local attacker the ability to use
    the AF_ALG-based skcipher interface to cause a denial
    of service (uninitialized-memory free and kernel crash)
    or have an unspecified other impact by executing a
    crafted sequence of system calls that use the
    blkcipher_walk API. Both the generic implementation
    (crypto/salsa20_generic.c) and x86 implementation
    (arch/x86/crypto/salsa20_glue.c) of Salsa20 are
    vulnerable.(CVE-2017-17805)

  - The HMAC implementation (crypto/hmac.c) in the Linux
    kernel, before 4.14.8, does not validate that the
    underlying cryptographic hash algorithm is unkeyed.
    This allows a local attacker, able to use the
    AF_ALG-based hash interface
    (CONFIG_CRYPTO_USER_API_HASH) and the SHA-3 hash
    algorithm (CONFIG_CRYPTO_SHA3), to cause a kernel stack
    buffer overflow by executing a crafted sequence of
    system calls that encounter a missing SHA-3
    initialization.(CVE-2017-17806)

  - The KEYS subsystem in the Linux kernel omitted an
    access-control check when writing a key to the current
    task's default keyring, allowing a local user to bypass
    security checks to the keyring. This compromises the
    validity of the keyring for those who rely on
    it.(CVE-2017-17807)

  - A flaw was found in the Linux kernel's implementation
    of i8042 serial ports. An attacker could cause a kernel
    panic if they are able to add and remove devices as the
    module is loaded.(CVE-2017-18079)

  - The Linux kernel, before version 4.14.3, is vulnerable
    to a denial of service in
    drivers/md/dm.c:dm_get_from_kobject() which can be
    caused by local users leveraging a race condition with
    __dm_destroy() during creation and removal of DM
    devices. Only privileged local users (with
    CAP_SYS_ADMIN capability) can directly perform the
    ioctl operations for dm device creation and removal and
    this would typically be outside the direct control of
    the unprivileged attacker.(CVE-2017-18203)

  - The madvise_willneed function in the Linux kernel
    allows local users to cause a denial of service
    (infinite loop) by triggering use of MADVISE_WILLNEED
    for a DAX mapping.(CVE-2017-18208)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1501
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4cf08299");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-18079");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-862.14.1.6_42",
        "kernel-devel-3.10.0-862.14.1.6_42",
        "kernel-headers-3.10.0-862.14.1.6_42",
        "kernel-tools-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-3.10.0-862.14.1.6_42",
        "kernel-tools-libs-devel-3.10.0-862.14.1.6_42",
        "perf-3.10.0-862.14.1.6_42",
        "python-perf-3.10.0-862.14.1.6_42"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
