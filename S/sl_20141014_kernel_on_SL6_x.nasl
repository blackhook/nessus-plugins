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
  script_id(78845);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/16");

  script_cve_id(
    "CVE-2013-2596",
    "CVE-2013-4483",
    "CVE-2014-0181",
    "CVE-2014-3122",
    "CVE-2014-3601",
    "CVE-2014-4608",
    "CVE-2014-4653",
    "CVE-2014-4654",
    "CVE-2014-4655",
    "CVE-2014-5045",
    "CVE-2014-5077"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/10/06");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20141014)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"* A NULL pointer dereference flaw was found in the way the Linux
kernel's Stream Control Transmission Protocol (SCTP) implementation
handled simultaneous connections between the same hosts. A remote
attacker could use this flaw to crash the system. (CVE-2014-5077,
Important)

* An integer overflow flaw was found in the way the Linux kernel's
Frame Buffer device implementation mapped kernel memory to user space
via the mmap syscall. A local user able to access a frame buffer
device file (/dev/fb*) could possibly use this flaw to escalate their
privileges on the system. (CVE-2013-2596, Important)

* A flaw was found in the way the ipc_rcu_putref() function in the
Linux kernel's IPC implementation handled reference counter
decrementing. A local, unprivileged user could use this flaw to
trigger an Out of Memory (OOM) condition and, potentially, crash the
system. (CVE-2013-4483, Moderate)

* It was found that the permission checks performed by the Linux
kernel when a netlink message was received were not sufficient. A
local, unprivileged user could potentially bypass these restrictions
by passing a netlink socket as stdout or stderr to a more privileged
process and altering the output of this process. (CVE-2014-0181,
Moderate)

* It was found that the try_to_unmap_cluster() function in the Linux
kernel's Memory Managment subsystem did not properly handle page
locking in certain cases, which could potentially trigger the BUG_ON()
macro in the mlock_vma_page() function. A local, unprivileged user
could use this flaw to crash the system. (CVE-2014-3122, Moderate)

* A flaw was found in the way the Linux kernel's kvm_iommu_map_pages()
function handled IOMMU mapping failures. A privileged user in a guest
with an assigned host device could use this flaw to crash the host.
(CVE-2014-3601, Moderate)

* Multiple use-after-free flaws were found in the way the Linux
kernel's Advanced Linux Sound Architecture (ALSA) implementation
handled user controls. A local, privileged user could use either of
these flaws to crash the system. (CVE-2014-4653, CVE-2014-4654,
CVE-2014-4655, Moderate)

* A flaw was found in the way the Linux kernel's VFS subsystem handled
reference counting when performing unmount operations on symbolic
links. A local, unprivileged user could use this flaw to exhaust all
available memory on the system or, potentially, trigger a
use-after-free error, resulting in a system crash or privilege
escalation. (CVE-2014-5045, Moderate)

* An integer overflow flaw was found in the way the
lzo1x_decompress_safe() function of the Linux kernel's LZO
implementation processed Literal Runs. A local attacker could, in
extremely rare cases, use this flaw to crash the system or,
potentially, escalate their privileges on the system. (CVE-2014-4608,
Low)

The system must be rebooted for this update to take effect.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=1615
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?398f36ec");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");

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
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"i386", reference:"kernel-debuginfo-common-i686-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-504.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-504.el6")) flag++;


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
