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
  script_id(92402);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-4565");

  script_name(english:"Scientific Linux Security Update : kernel on SL6.x i386/x86_64 (20160712)");
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
"Security Fix :

  - A flaw was found in the way certain interfaces of the
    Linux kernel's Infiniband subsystem used write() as
    bi-directional ioctl() replacement, which could lead to
    insufficient memory security checks when being invoked
    using the the splice() system call. A local unprivileged
    user on a system with either Infiniband hardware present
    or RDMA Userspace Connection Manager Access module
    explicitly loaded, could use this flaw to escalate their
    privileges on the system. (CVE-2016-4565, Important)

This update also fixes the following bugs :

  - When providing some services and using the Integrated
    Services Digital Network (ISDN), the system could
    terminate unexpectedly due to the call of the
    tty_ldisc_flush() function. The provided patch removes
    this call and the system no longer hangs in the
    described scenario.

  - An update to the Scientific Linux 6.8 kernel added calls
    of two functions provided by the ipv6.ko kernel module,
    which added a dependency on that module. On systems
    where ipv6.ko was prevented from being loaded, the
    nfsd.ko and lockd.ko modules were unable to be loaded.
    Consequently, it was not possible to run an NFS server
    or to mount NFS file systems as a client. The underlying
    source code has been fixed by adding the symbol_get()
    function, which determines if nfsd.ko and lock.ko are
    loaded into memory and calls them through function
    pointers, not directly. As a result, the aforementioned
    kernel modules are allowed to be loaded even if ipv6.ko
    is not, and the NFS mount works as expected.

  - After upgrading the kernel, CPU load average increased
    compared to the prior kernel version due to the
    modification of the scheduler. The provided patch set
    reverts the calculation algorithm of this load average
    to the the previous version thus resulting in relatively
    lower values under the same system load.

Updated dracut packages have also been included to satisfy
dependencies."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1607&L=scientific-linux-errata&F=&S=&P=5413
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dc563883"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-caps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-fips-aesni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-generic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:dracut-tools");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"dracut-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-caps-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-fips-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-fips-aesni-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-generic-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-kernel-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-network-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"dracut-tools-004-409.el6_8.2")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-abi-whitelists-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-debuginfo-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debug-devel-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-debuginfo-common-i686-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-devel-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-doc-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-firmware-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"kernel-headers-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"perf-debuginfo-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-2.6.32-642.3.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"python-perf-debuginfo-2.6.32-642.3.1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dracut / dracut-caps / dracut-fips / dracut-fips-aesni / etc");
}
