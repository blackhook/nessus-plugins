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
  script_id(69503);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3552", "CVE-2012-6544", "CVE-2013-2146", "CVE-2013-2206", "CVE-2013-2224", "CVE-2013-2232", "CVE-2013-2237");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20130827)");
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
"This update fixes the following security issues :

  - A flaw was found in the way the Linux kernel's Stream
    Control Transmission Protocol (SCTP) implementation
    handled duplicate cookies. If a local user queried SCTP
    connection information at the same time a remote
    attacker has initialized a crafted SCTP connection to
    the system, it could trigger a NULL pointer dereference,
    causing the system to crash. (CVE-2013-2206, Important)

  - It was found that the fix for CVE-2012-3552 released via
    SLSA-2012:1304 introduced an invalid free flaw in the
    Linux kernel's TCP/IP protocol suite implementation. A
    local, unprivileged user could use this flaw to corrupt
    kernel memory via crafted sendmsg() calls, allowing them
    to cause a denial of service or, potentially, escalate
    their privileges on the system. (CVE-2013-2224,
    Important)

  - A flaw was found in the Linux kernel's Performance
    Events implementation. On systems with certain Intel
    processors, a local, unprivileged user could use this
    flaw to cause a denial of service by leveraging the perf
    subsystem to write into the reserved bits of the
    OFFCORE_RSP_0 and OFFCORE_RSP_1 model-specific
    registers. (CVE-2013-2146, Moderate)

  - An invalid pointer dereference flaw was found in the
    Linux kernel's TCP/IP protocol suite implementation. A
    local, unprivileged user could use this flaw to crash
    the system or, potentially, escalate their privileges on
    the system by using sendmsg() with an IPv6 socket
    connected to an IPv4 destination. (CVE-2013-2232,
    Moderate)

  - Information leak flaws in the Linux kernel's Bluetooth
    implementation could allow a local, unprivileged user to
    leak kernel memory to user- space. (CVE-2012-6544, Low)

  - An information leak flaw in the Linux kernel could allow
    a privileged, local user to leak kernel memory to
    user-space. (CVE-2013-2237, Low)

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1308&L=scientific-linux-errata&T=0&P=1468
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cf91b714"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/08/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-358.18.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-358.18.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-debuginfo / kernel-debug-devel / etc");
}
