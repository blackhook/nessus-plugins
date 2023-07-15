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
  script_id(85198);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3184", "CVE-2014-3940", "CVE-2014-4652", "CVE-2014-8133", "CVE-2014-8709", "CVE-2014-9683", "CVE-2015-0239", "CVE-2015-3339");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20150722)");
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
"* A flaw was found in the way Linux kernel's Transparent Huge Pages
(THP) implementation handled non-huge page migration. A local,
unprivileged user could use this flaw to crash the kernel by migrating
transparent hugepages. (CVE-2014-3940, Moderate)

* A buffer overflow flaw was found in the way the Linux kernel's
eCryptfs implementation decoded encrypted file names. A local,
unprivileged user could use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-9683,
Moderate)

* A race condition flaw was found between the chown and execve system
calls. When changing the owner of a setuid user binary to root, the
race condition could momentarily make the binary setuid root. A local,
unprivileged user could potentially use this flaw to escalate their
privileges on the system. (CVE-2015-3339, Moderate)

* Multiple out-of-bounds write flaws were found in the way the Cherry
Cymotion keyboard driver, KYE/Genius device drivers, Logitech device
drivers, Monterey Genius KB29E keyboard driver, Petalynx Maxter remote
control driver, and Sunplus wireless desktop driver handled HID
reports with an invalid report descriptor size. An attacker with
physical access to the system could use either of these flaws to write
data past an allocated memory buffer. (CVE-2014-3184, Low)

* An information leak flaw was found in the way the Linux kernel's
Advanced Linux Sound Architecture (ALSA) implementation handled access
of the user control's state. A local, privileged user could use this
flaw to leak kernel memory to user space. (CVE-2014-4652, Low)

* It was found that the espfix functionality could be bypassed by
installing a 16-bit RW data segment into GDT instead of LDT (which
espfix checks), and using that segment on the stack. A local,
unprivileged user could potentially use this flaw to leak kernel stack
addresses. (CVE-2014-8133, Low)

* An information leak flaw was found in the Linux kernel's IEEE 802.11
wireless networking implementation. When software encryption was used,
a remote attacker could use this flaw to leak up to 8 bytes of
plaintext. (CVE-2014-8709, Low)

* It was found that the Linux kernel KVM subsystem's sysenter
instruction emulation was not sufficient. An unprivileged guest user
could use this flaw to escalate their privileges by tricking the
hypervisor to emulate a SYSENTER instruction in 16-bit mode, if the
guest OS did not initialize the SYSENTER model-specific registers
(MSRs). Note: Certified guest operating systems for Scientific Linux
with KVM do initialize the SYSENTER MSRs and are thus not vulnerable
to this issue when running on a KVM hypervisor. (CVE-2015-0239, Low)

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=7966
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e432e14d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-573.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-573.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-abi-whitelists / kernel-debug / etc");
}
