#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-914.
#

include("compat.inc");

if (description)
{
  script_id(104180);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/06/04");

  script_cve_id("CVE-2017-1000251", "CVE-2017-12154", "CVE-2017-12192", "CVE-2017-14340", "CVE-2017-14991", "CVE-2017-15274");
  script_xref(name:"ALAS", value:"2017-914");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2017-914) (BlueBorne)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"stack buffer overflow in the native Bluetooth stack

A stack buffer overflow flaw was found in the way the Bluetooth
subsystem of the Linux kernel processed pending L2CAP configuration
responses from a client. On systems with the stack protection feature
enabled in the kernel (CONFIG_CC_STACKPROTECTOR=y, which is enabled on
all architectures other than s390x and ppc64[le]), an unauthenticated
attacker able to initiate a connection to a system via Bluetooth could
use this flaw to crash the system. Due to the nature of the stack
protection feature, code execution cannot be fully ruled out, although
we believe it is unlikely. On systems without the stack protection
feature (ppc64[le]; the Bluetooth modules are not built on s390x), an
unauthenticated attacker able to initiate a connection to a system via
Bluetooth could use this flaw to remotely execute arbitrary code on
the system with ring 0 (kernel) privileges. (CVE-2017-1000251)

dereferencing NULL payload with nonzero length

A flaw was found in the implementation of associative arrays where the
add_key systemcall and KEYCTL_UPDATE operations allowed for a NULL
payload with a nonzero length. When accessing the payload within this
length parameters value, an unprivileged user could trivially cause a
NULL pointer dereference (kernel oops). (CVE-2017-15274)

xfs: unprivileged user kernel oops

A flaw was found where the XFS filesystem code mishandles a
user-settable inode flag in the Linux kernel prior to 4.14-rc1. This
can cause a local denial of service via a kernel
panic.(CVE-2017-14340)

Information leak in the scsi driver

The sg_ioctl() function in 'drivers/scsi/sg.c' in the Linux kernel,
from version 4.12-rc1 to 4.14-rc2, allows local users to obtain
sensitive information from uninitialized kernel heap-memory locations
via an SG_GET_REQUEST_TABLE ioctl call for '/dev/sg0'.
(CVE-2017-14991)

kvm: nVMX: L2 guest could access hardware(L0) CR8 register

Linux kernel built with the KVM visualization support (CONFIG_KVM),
with nested visualization (nVMX) feature enabled (nested=1), is
vulnerable to a crash due to disabled external interrupts. As L2 guest
could access (r/w) hardware CR8 register of the host(L0). In a nested
visualization setup, L2 guest user could use this flaw to potentially
crash the host(L0) resulting in DoS. (CVE-2017-12154)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-914.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.9.58-18.51.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.9.58-18.51.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
