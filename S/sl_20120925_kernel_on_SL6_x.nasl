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
  script_id(62346);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2313", "CVE-2012-2384", "CVE-2012-2390", "CVE-2012-3430", "CVE-2012-3552");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20120925)");
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
"The kernel packages contain the Linux kernel, the core of any Linux
operating system.

This update fixes the following security issues :

  - An integer overflow flaw was found in the
    i915_gem_do_execbuffer() function in the Intel i915
    driver in the Linux kernel. A local, unprivileged user
    could use this flaw to cause a denial of service. This
    issue only affected 32-bit systems. (CVE-2012-2384,
    Moderate)

  - A memory leak flaw was found in the way the Linux
    kernel's memory subsystem handled resource clean up in
    the mmap() failure path when the MAP_HUGETLB flag was
    set. A local, unprivileged user could use this flaw to
    cause a denial of service. (CVE-2012-2390, Moderate)

  - A race condition was found in the way access to
    inet->opt ip_options was synchronized in the Linux
    kernel's TCP/IP protocol suite implementation. Depending
    on the network facing applications running on the
    system, a remote attacker could possibly trigger this
    flaw to cause a denial of service. A local, unprivileged
    user could use this flaw to cause a denial of service
    regardless of the applications the system runs.
    (CVE-2012-3552, Moderate)

  - A flaw was found in the way the Linux kernel's dl2k
    driver, used by certain D-Link Gigabit Ethernet
    adapters, restricted IOCTLs. A local, unprivileged user
    could use this flaw to issue potentially harmful IOCTLs,
    which could cause Ethernet adapters using the dl2k
    driver to malfunction (for example, losing network
    connectivity). (CVE-2012-2313, Low)

  - A flaw was found in the way the msg_namelen variable in
    the rds_recvmsg() function of the Linux kernel's
    Reliable Datagram Sockets (RDS) protocol implementation
    was initialized. A local, unprivileged user could use
    this flaw to leak kernel stack memory to user-space.
    (CVE-2012-3430, Low)

This update also fixes several bugs.

Users should upgrade to these updated packages, which contain
backported patches to correct these issues, and fix the bugs noted.
The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1209&L=scientific-linux-errata&T=0&P=4180
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?29073793"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-279.9.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-279.9.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-devel / kernel-devel / etc");
}
