#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(82254);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3690", "CVE-2014-3940", "CVE-2014-7825", "CVE-2014-7826", "CVE-2014-8086", "CVE-2014-8160", "CVE-2014-8172", "CVE-2014-8173", "CVE-2014-8709", "CVE-2014-8884", "CVE-2015-0274");

  script_name(english:"Scientific Linux Security Update : kernel on SL7.x x86_64 (20150305)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"* A flaw was found in the way the Linux kernel's XFS file system
handled replacing of remote attributes under certain conditions. A
local user with access to XFS file system mount could potentially use
this flaw to escalate their privileges on the system. (CVE-2015-0274,
Important)

* It was found that the Linux kernel's KVM implementation did not
ensure that the host CR4 control register value remained unchanged
across VM entries on the same virtual CPU. A local, unprivileged user
could use this flaw to cause denial of service on the system.
(CVE-2014-3690, Moderate)

* A flaw was found in the way Linux kernel's Transparent Huge Pages
(THP) implementation handled non-huge page migration. A local,
unprivileged user could use this flaw to crash the kernel by migrating
transparent hugepages. (CVE-2014-3940, Moderate)

* An out-of-bounds memory access flaw was found in the syscall tracing
functionality of the Linux kernel's perf subsystem. A local,
unprivileged user could use this flaw to crash the system.
(CVE-2014-7825, Moderate)

* An out-of-bounds memory access flaw was found in the syscall tracing
functionality of the Linux kernel's ftrace subsystem. On a system with
ftrace syscall tracing enabled, a local, unprivileged user could use
this flaw to crash the system, or escalate their privileges.
(CVE-2014-7826, Moderate)

* A race condition flaw was found in the Linux kernel's ext4 file
system implementation that allowed a local, unprivileged user to crash
the system by simultaneously writing to a file and toggling the
O_DIRECT flag using fcntl(F_SETFL) on that file. (CVE-2014-8086,
Moderate)

* A flaw was found in the way the Linux kernel's netfilter subsystem
handled generic protocol tracking. As demonstrated in the Stream
Control Transmission Protocol (SCTP) case, a remote attacker could use
this flaw to bypass intended iptables rule restrictions when the
associated connection tracking module was not loaded on the system.
(CVE-2014-8160, Moderate)

* It was found that due to excessive files_lock locking, a soft lockup
could be triggered in the Linux kernel when performing asynchronous
I/O operations. A local, unprivileged user could use this flaw to
crash the system. (CVE-2014-8172, Moderate)

* A NULL pointer dereference flaw was found in the way the Linux
kernel's madvise MADV_WILLNEED functionality handled page table
locking. A local, unprivileged user could use this flaw to crash the
system. (CVE-2014-8173, Moderate)

* An information leak flaw was found in the Linux kernel's IEEE 802.11
wireless networking implementation. When software encryption was used,
a remote attacker could use this flaw to leak up to 8 bytes of
plaintext. (CVE-2014-8709, Low)

* A stack-based buffer overflow flaw was found in the
TechnoTrend/Hauppauge DEC USB device driver. A local user with write
access to the corresponding device could use this flaw to crash the
kernel or, potentially, elevate their privileges on the system.
(CVE-2014-8884, Low)

* Users of kernel modules may need to upgrade the module to maintain
compatibility.

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1503&L=scientific-linux-errata&T=0&P=3369
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?81e9d1ab"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-abi-whitelists-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-debuginfo-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debug-devel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-devel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kernel-doc-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-headers-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-debuginfo-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kernel-tools-libs-devel-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"perf-debuginfo-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-3.10.0-229.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-perf-debuginfo-3.10.0-229.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
