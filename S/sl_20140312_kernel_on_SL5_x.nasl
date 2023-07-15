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
  script_id(73012);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-2929", "CVE-2013-4483", "CVE-2013-4554", "CVE-2013-6381", "CVE-2013-6383", "CVE-2013-6885", "CVE-2013-7263", "CVE-2013-7265");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64 (20140312)");
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
"* A buffer overflow flaw was found in the way the qeth_snmp_command()
function in the Linux kernel's QETH network device driver
implementation handled SNMP IOCTL requests with an out-of-bounds
length. A local, unprivileged user could use this flaw to crash the
system or, potentially, escalate their privileges on the system.
(CVE-2013-6381, Important)

* A flaw was found in the way the ipc_rcu_putref() function in the
Linux kernel's IPC implementation handled reference counter
decrementing. A local, unprivileged user could use this flaw to
trigger an Out of Memory (OOM) condition and, potentially, crash the
system. (CVE-2013-4483, Moderate)

* It was found that the Xen hypervisor implementation did not
correctly check privileges of hypercall attempts made by HVM guests,
allowing hypercalls to be invoked from protection rings 1 and 2 in
addition to ring 0. A local attacker in an HVM guest able to execute
code on privilege levels 1 and 2 could potentially use this flaw to
further escalate their privileges in that guest. Note: Xen HVM guests
running unmodified versions of Scientific Linux and Microsoft Windows
are not affected by this issue because they are known to only use
protection rings 0 (kernel) and 3 (userspace). (CVE-2013-4554,
Moderate)

* A flaw was found in the way the Linux kernel's Adaptec RAID
controller (aacraid) checked permissions of compat IOCTLs. A local
attacker could use this flaw to bypass intended security restrictions.
(CVE-2013-6383, Moderate)

A privileged user in a guest running under the Xen hypervisor could
use this flaw to cause a denial of service on the host system. This
update adds a workaround to the Xen hypervisor implementation, which
mitigates the AMD CPU issue. Note: this issue only affects AMD Family
16h Models 00h-0Fh Processors. Non-AMD CPUs are not vulnerable.
(CVE-2013-6885, Moderate)

* It was found that certain protocol handlers in the Linux kernel's
networking implementation could set the addr_len value without
initializing the associated data structure. A local, unprivileged user
could use this flaw to leak kernel stack memory to user space using
the recvmsg, recvfrom, and recvmmsg system calls. (CVE-2013-7263, Low)

* A flaw was found in the way the get_dumpable() function return value
was interpreted in the ptrace subsystem of the Linux kernel. When
'fs.suid_dumpable' was set to 2, a local, unprivileged local user
could use this flaw to bypass intended ptrace restrictions and obtain
potentially sensitive information. (CVE-2013-2929, Low)

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1403&L=scientific-linux-errata&T=0&P=822
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f00d3331"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-debuginfo-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/14");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-371.6.1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-371.6.1.el5")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-debuginfo / kernel-PAE-devel / etc");
}
