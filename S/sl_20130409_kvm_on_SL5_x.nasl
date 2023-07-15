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
  script_id(65906);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1796", "CVE-2013-1797", "CVE-2013-1798");

  script_name(english:"Scientific Linux Security Update : kvm on SL5.x x86_64 (20130409)");
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
"A flaw was found in the way KVM handled guest time updates when the
buffer the guest registered by writing to the MSR_KVM_SYSTEM_TIME
machine state register (MSR) crossed a page boundary. A privileged
guest user could use this flaw to crash the host or, potentially,
escalate their privileges, allowing them to execute arbitrary code at
the host kernel level. (CVE-2013-1796)

A potential use-after-free flaw was found in the way KVM handled guest
time updates when the GPA (guest physical address) the guest
registered by writing to the MSR_KVM_SYSTEM_TIME machine state
register (MSR) fell into a movable or removable memory region of the
hosting user-space process (by default, QEMU-KVM) on the host. If that
memory region is deregistered from KVM using
KVM_SET_USER_MEMORY_REGION and the allocated virtual memory reused, a
privileged guest user could potentially use this flaw to escalate
their privileges on the host. (CVE-2013-1797)

A flaw was found in the way KVM emulated IOAPIC (I/O Advanced
Programmable Interrupt Controller). A missing validation check in the
ioapic_read_indirect() function could allow a privileged guest user to
crash the host, or read a substantial portion of host kernel memory.
(CVE-2013-1798)

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1304&L=scientific-linux-errata&T=0&P=701
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ba2bc32f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:H/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmod-kvm-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kvm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kvm-qemu-img");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kvm-tools");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-83-262.el5_9.3")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kmod-kvm-debug-83-262.el5_9.3")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-83-262.el5_9.3")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-debuginfo-83-262.el5_9.3")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-qemu-img-83-262.el5_9.3")) flag++;
if (rpm_check(release:"SL5", cpu:"x86_64", reference:"kvm-tools-83-262.el5_9.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kmod-kvm / kmod-kvm-debug / kvm / kvm-debuginfo / kvm-qemu-img / etc");
}
