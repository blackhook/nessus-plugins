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
  script_id(73200);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1860", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0101");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20140325)");
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
"* A flaw was found in the way the get_rx_bufs() function in the
vhost_net implementation in the Linux kernel handled error conditions
reported by the vhost_get_vq_desc() function. A privileged guest user
could use this flaw to crash the host. (CVE-2014-0055, Important)

* A flaw was found in the way the Linux kernel processed an
authenticated COOKIE_ECHO chunk during the initialization of an SCTP
connection. A remote attacker could use this flaw to crash the system
by initiating a specially crafted SCTP handshake in order to trigger a
NULL pointer dereference on the system. (CVE-2014-0101, Important)

* A flaw was found in the way the Linux kernel's CIFS implementation
handled uncached write operations with specially crafted iovec
structures. An unprivileged local user with access to a CIFS share
could use this flaw to crash the system, leak kernel memory, or,
potentially, escalate their privileges on the system. Note: the
default cache settings for CIFS mounts on Scientific Linux 6 prohibit
a successful exploitation of this issue. (CVE-2014-0069, Moderate)

* A heap-based buffer overflow flaw was found in the Linux kernel's
cdc- wdm driver, used for USB CDC WCM device management. An attacker
with physical access to a system could use this flaw to cause a denial
of service or, potentially, escalate their privileges. (CVE-2013-1860,
Low)

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=2449
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6ae65dfb"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-abi-whitelists");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-431.11.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-431.11.2.el6")) flag++;


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
