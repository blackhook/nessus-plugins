#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2007:0939 and 
# Oracle Linux Security Advisory ELSA-2007-0939 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67580);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/24");

  script_cve_id("CVE-2006-6921", "CVE-2007-2878", "CVE-2007-3105", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4571");
  script_bugtraq_id(25216, 25244, 25348, 25387, 25672, 25807);
  script_xref(name:"RHSA", value:"2007:0939");

  script_name(english:"Oracle Linux 4 : kernel (ELSA-2007-0939)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2007:0939 :

Updated kernel packages that fix various security issues in the Red
Hat Enterprise Linux 4 kernel are now available.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The Linux kernel is the core of the operating system.

These updated kernel packages contain fixes for the following security
issues :

* A flaw was found in the handling of process death signals. This
allowed a local user to send arbitrary signals to the suid-process
executed by that user. A successful exploitation of this flaw depends
on the structure of the suid-program and its signal handling.
(CVE-2007-3848, Important)

* A flaw was found in the CIFS file system. This could cause the umask
values of a process to not be honored on CIFS file systems where UNIX
extensions are supported. (CVE-2007-3740, Important)

* A flaw was found in the VFAT compat ioctl handling on 64-bit
systems. This allowed a local user to corrupt a kernel_dirent struct
and cause a denial of service. (CVE-2007-2878, Important)

* A flaw was found in the Advanced Linux Sound Architecture (ALSA). A
local user who had the ability to read the /proc/driver/snd-page-alloc
file could see portions of kernel memory. (CVE-2007-4571, Moderate)

* A flaw was found in the aacraid SCSI driver. This allowed a local
user to make ioctl calls to the driver that should be restricted to
privileged users. (CVE-2007-4308, Moderate)

* A flaw was found in the stack expansion when using the hugetlb
kernel on PowerPC systems. This allowed a local user to cause a denial
of service. (CVE-2007-3739, Moderate)

* A flaw was found in the handling of zombie processes. A local user
could create processes that would not be properly reaped which could
lead to a denial of service. (CVE-2006-6921, Moderate)

* A flaw was found in the CIFS file system handling. The mount option
'sec=' did not enable integrity checking or produce an error message
if used. (CVE-2007-3843, Low)

* A flaw was found in the random number generator implementation that
allowed a local user to cause a denial of service or possibly gain
privileges. This flaw could be exploited if the root user raised the
default wakeup threshold over the size of the output pool.
(CVE-2007-3105, Low)

Additionally, the following bugs were fixed :

* A flaw was found in the kernel netpoll code, creating a potential
deadlock condition. If the xmit_lock for a given network interface is
held, and a subsequent netpoll event is generated from within the lock
owning context (a console message for example), deadlock on that cpu
will result, because the netpoll code will attempt to re-acquire the
xmit_lock. The fix is to, in the netpoll code, only attempt to take
the lock, and fail if it is already acquired (rather than block on
it), and queue the message to be sent for later delivery. Any user of
netpoll code in the kernel (netdump or netconsole services), is
exposed to this problem, and should resolve the issue by upgrading to
this kernel release immediately.

* A flaw was found where, under 64-bit mode (x86_64), AMD processors
were not able to address greater than a 40-bit physical address space;
and Intel processors were only able to address up to a 36-bit physical
address space. The fix is to increase the physical addressing for an
AMD processor to 48 bits, and an Intel processor to 38 bits. Please
see the Red Hat Knowledgebase for more detailed information.

* A flaw was found in the xenU kernel that may prevent a
paravirtualized guest with more than one CPU from starting when
running under an Enterprise Linux 5.1 hypervisor. The fix is to allow
your Enterprise Linux 4 Xen SMP guests to boot under a 5.1 hypervisor.
Please see the Red Hat Knowledgebase for more detailed information.

Red Hat Enterprise Linux 4 users are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2007-November/000376.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-hugemem-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-largesmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");
include("ksplice.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

if (get_one_kb_item("Host/ksplice/kernel-cves"))
{
  cve_list = make_list("CVE-2006-6921", "CVE-2007-2878", "CVE-2007-3105", "CVE-2007-3739", "CVE-2007-3740", "CVE-2007-3843", "CVE-2007-3848", "CVE-2007-4308", "CVE-2007-4571");  
  if (ksplice_cves_check(cve_list))
  {
    audit(AUDIT_PATCH_INSTALLED, "KSplice hotfix for ELSA-2007-0939");
  }
  else
  {
    __rpm_report = ksplice_reporting_text();
  }
}

kernel_major_minor = get_kb_item("Host/uname/major_minor");
if (empty_or_null(kernel_major_minor)) exit(1, "Unable to determine kernel major-minor level.");
expected_kernel_major_minor = "2.6";
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, "running kernel level " + expected_kernel_major_minor + ", it is running kernel level " + kernel_major_minor);

flag = 0;
if (rpm_exists(release:"EL4", rpm:"kernel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-doc-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-doc-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-doc-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-hugemem-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-hugemem-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-largesmp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-largesmp-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-smp-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-smp-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-smp-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"i386", reference:"kernel-xenU-devel-2.6.9-55.0.12.0.1.EL")) flag++;
if (rpm_exists(release:"EL4", rpm:"kernel-xenU-devel-2.6.9") && rpm_check(release:"EL4", cpu:"x86_64", reference:"kernel-xenU-devel-2.6.9-55.0.12.0.1.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "affected kernel");
}
