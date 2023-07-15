#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102997);
  script_version("3.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2016-9604",
    "CVE-2017-1000365",
    "CVE-2017-11176",
    "CVE-2017-11473",
    "CVE-2017-11600",
    "CVE-2017-12762",
    "CVE-2017-7541",
    "CVE-2017-7542"
  );

  script_name(english:"EulerOS 2.0 SP1 : kernel (EulerOS-SA-2017-1159)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The mq_notify function in the Linux kernel through
    4.11.9 does not set the sock pointer to NULL upon entry
    into the retry logic. During a user-space close of a
    Netlink socket, it allows attackers to cause a denial
    of service (use-after-free) or possibly have
    unspecified other impact.(CVE-2017-11176)

  - The brcmf_cfg80211_mgmt_tx function in
    drivers/net/wireless/broadcom/brcm80211/brcmfmac/
    cfg80211.c in the Linux kernel before 4.12.3 allows
    local users to cause a denial of service (buffer
    overflow and system crash) or possibly gain privileges
    via a crafted NL80211_CMD_FRAME Netlink
    packet.(CVE-2017-7541)

  - The ip6_find_1stfragopt function in
    net/ipv6/output_core.c in the Linux kernel through
    4.12.3 allows local users to cause a denial of service
    (integer overflow and infinite loop) by leveraging the
    ability to open a raw socket.(CVE-2017-7542)

  - Buffer overflow in the mp_override_legacy_irq()
    function in arch/x86/kernel/acpi/boot.c in the Linux
    kernel through 4.12.2 allows local users to gain
    privileges via a crafted ACPI table.(CVE-2017-11473)

  - net/xfrm/xfrm_policy.c in the Linux kernel through
    4.12.3, when CONFIG_XFRM_MIGRATE is enabled, does not
    ensure that the dir value of xfrm_userpolicy_id is
    XFRM_POLICY_MAX or less, which allows local users to
    cause a denial of service (out-of-bounds access) or
    possibly have unspecified other impact via an
    XFRM_MSG_MIGRATE xfrm Netlink message.(CVE-2017-11600)

  - It was discovered that root can gain direct access to
    an internal keyring, such as '.dns_resolver' in RHEL-7
    or '.builtin_trusted_keys' upstream, by joining it as
    its session keyring. This allows root to bypass module
    signature verification by adding a new public key of
    its own devising to the keyring.(CVE-2016-9604)

  - A user-controlled buffer is copied into a local buffer
    of constant size using strcpy without a length check
    which can cause a buffer overflow. This affects the
    Linux kernel 4.9-stable tree, 4.12-stable tree,
    3.18-stable tree, and 4.4-stable tree.(CVE-2017-12762)

  - The Linux Kernel imposes a size restriction on the
    arguments and environmental strings passed through
    RLIMIT_STACK/RLIM_INFINITY (1/4 of the size), but does
    not take the argument and environment pointers into
    account, which allows attackers to bypass this
    limitation. This affects Linux Kernel versions 4.11.5
    and earlier. It appears that this feature was
    introduced in the Linux Kernel version
    2.6.23.(CVE-2017-1000365)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1159
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dcc8f11e");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

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
if (isnull(sp) || sp !~ "^(1)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP1", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["kernel-3.10.0-229.49.1.142",
        "kernel-debug-3.10.0-229.49.1.142",
        "kernel-debuginfo-3.10.0-229.49.1.142",
        "kernel-debuginfo-common-x86_64-3.10.0-229.49.1.142",
        "kernel-devel-3.10.0-229.49.1.142",
        "kernel-headers-3.10.0-229.49.1.142",
        "kernel-tools-3.10.0-229.49.1.142",
        "kernel-tools-libs-3.10.0-229.49.1.142",
        "perf-3.10.0-229.49.1.142",
        "python-perf-3.10.0-229.49.1.142"];

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
