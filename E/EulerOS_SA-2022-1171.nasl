#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158288);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/09");

  script_cve_id(
    "CVE-2020-27068",
    "CVE-2020-36322",
    "CVE-2020-36386",
    "CVE-2021-3753",
    "CVE-2021-20322",
    "CVE-2021-34981",
    "CVE-2021-37576",
    "CVE-2021-40490",
    "CVE-2021-42008",
    "CVE-2021-42739"
  );

  script_name(english:"EulerOS 2.0 SP3 : kernel (EulerOS-SA-2022-1171)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the kernel packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - In the nl80211_policy policy of nl80211.c, there is a possible out of bounds read due to a missing bounds
    check. This could lead to local information disclosure with System execution privileges needed. User
    interaction is not required for exploitation.Product: AndroidVersions: Android kernelAndroid ID:
    A-119770583 (CVE-2020-27068)

  - An issue was discovered in the FUSE filesystem implementation in the Linux kernel before 5.10.6, aka
    CID-5d069dbe8aaf. fuse_do_getattr() calls make_bad_inode() in inappropriate situations, causing a system
    crash. NOTE: the original fix for this vulnerability was incomplete, and its incompleteness is tracked as
    CVE-2021-28950. (CVE-2020-36322)

  - An issue was discovered in the Linux kernel before 5.8.1. net/bluetooth/hci_event.c has a slab out-of-
    bounds read in hci_extended_inquiry_result_evt, aka CID-51c19bf3d5cf. (CVE-2020-36386)

  - A flaw in the processing of received ICMP errors (ICMP fragment needed and ICMP redirect) in the Linux
    kernel functionality was found to allow the ability to quickly scan open UDP ports. This flaw allows an
    off-path remote user to effectively bypass the source port UDP randomization. The highest threat from this
    vulnerability is to confidentiality and possibly integrity, because software that relies on UDP source
    port randomization are indirectly affected as well. (CVE-2021-20322)

  - A race problem was seen in the vt_k_ioctl in drivers/tty/vt/vt_ioctl.c in the Linux kernel, which may
    cause an out of bounds read in vt as the write access to vc_mode is not protected by lock-in vt_ioctl
    (KDSETMDE). The highest threat from this vulnerability is to data confidentiality. (CVE-2021-3753)

  - arch/powerpc/kvm/book3s_rtas.c in the Linux kernel through 5.13.5 on the powerpc platform allows KVM guest
    OS users to cause host OS memory corruption via rtas_args.nargs, aka CID-f62f3c20647e. (CVE-2021-37576)

  - A race condition was discovered in ext4_write_inline_data_end in fs/ext4/inline.c in the ext4 subsystem in
    the Linux kernel through 5.13.13. (CVE-2021-40490)

  - The decode_data function in drivers/net/hamradio/6pack.c in the Linux kernel before 5.13.13 has a slab
    out-of-bounds write. Input from a process that has the CAP_NET_ADMIN capability can lead to root access.
    (CVE-2021-42008)

  - The firewire subsystem in the Linux kernel through 5.14.13 has a buffer overflow related to
    drivers/media/firewire/firedtv-avc.c and drivers/media/firewire/firedtv-ci.c, because avc_ca_pmt
    mishandles bounds checking. (CVE-2021-42739)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1171
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?48ef48ab");
  script_set_attribute(attribute:"solution", value:
"Update the affected kernel packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27068");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python-perf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "kernel-3.10.0-514.44.5.10.h349",
  "kernel-debuginfo-3.10.0-514.44.5.10.h349",
  "kernel-debuginfo-common-x86_64-3.10.0-514.44.5.10.h349",
  "kernel-devel-3.10.0-514.44.5.10.h349",
  "kernel-headers-3.10.0-514.44.5.10.h349",
  "kernel-tools-3.10.0-514.44.5.10.h349",
  "kernel-tools-libs-3.10.0-514.44.5.10.h349",
  "perf-3.10.0-514.44.5.10.h349",
  "python-perf-3.10.0-514.44.5.10.h349"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
