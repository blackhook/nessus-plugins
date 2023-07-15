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
  script_id(76157);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/25");

  script_cve_id(
    "CVE-2013-6378",
    "CVE-2014-0203",
    "CVE-2014-1737",
    "CVE-2014-1738",
    "CVE-2014-1874",
    "CVE-2014-2039",
    "CVE-2014-3153"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20140619)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"* A flaw was found in the way the Linux kernel's futex subsystem
handled the requeuing of certain Priority Inheritance (PI) futexes. A
local, unprivileged user could use this flaw to escalate their
privileges on the system. (CVE-2014-3153, Important)

* A flaw was found in the way the Linux kernel's floppy driver handled
user space provided data in certain error code paths while processing
FDRAWCMD IOCTL commands. A local user with write access to /dev/fdX
could use this flaw to free (using the kfree() function) arbitrary
kernel memory. (CVE-2014-1737, Important)

* It was found that the Linux kernel's floppy driver leaked internal
kernel memory addresses to user space during the processing of the
FDRAWCMD IOCTL command. A local user with write access to /dev/fdX
could use this flaw to obtain information about the kernel heap
arrangement. (CVE-2014-1738, Low)

Note: A local user with write access to /dev/fdX could use these two
flaws (CVE-2014-1737 in combination with CVE-2014-1738) to escalate
their privileges on the system.

* It was discovered that the proc_ns_follow_link() function did not
properly return the LAST_BIND value in the last pathname component as
is expected for procfs symbolic links, which could lead to excessive
freeing of memory and consequent slab corruption. A local,
unprivileged user could use this flaw to crash the system.
(CVE-2014-0203, Moderate)

* A flaw was found in the way the Linux kernel handled exceptions when
user-space applications attempted to use the linkage stack. On IBM
S/390 systems, a local, unprivileged user could use this flaw to crash
the system. (CVE-2014-2039, Moderate)

* An invalid pointer dereference flaw was found in the Marvell 8xxx
Libertas WLAN (libertas) driver in the Linux kernel. A local user able
to write to a file that is provided by the libertas driver and located
on the debug file system (debugfs) could use this flaw to crash the
system. Note: The debugfs file system must be mounted locally to
exploit this issue. It is not mounted by default. (CVE-2013-6378, Low)

* A denial of service flaw was discovered in the way the Linux
kernel's SELinux implementation handled files with an empty SELinux
security context. A local user who has the CAP_MAC_ADMIN capability
could use this flaw to crash the system. (CVE-2014-1874, Low)

The system must be rebooted for this update to take effect.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1406&L=scientific-linux-errata&T=0&P=2228
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5596ce7b");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Android "Towelroot" Futex Requeue Kernel Exploit');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/20");

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
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-431.20.3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-431.20.3.el6")) flag++;


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
