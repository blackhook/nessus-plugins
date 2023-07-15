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
  script_id(70577);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0343", "CVE-2013-4299", "CVE-2013-4345", "CVE-2013-4368");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64 (20131022)");
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
"  - A flaw was found in the way the Linux kernel handled the
    creation of temporary IPv6 addresses. If the IPv6
    privacy extension was enabled
    (/proc/sys/net/ipv6/conf/eth0/use_tempaddr is set to
    '2'), an attacker on the local network could disable
    IPv6 temporary address generation, leading to a
    potential information disclosure. (CVE-2013-0343,
    Moderate)

  - An information leak flaw was found in the way Linux
    kernel's device mapper subsystem, under certain
    conditions, interpreted data written to snapshot block
    devices. An attacker could use this flaw to read data
    from disk blocks in free space, which are normally
    inaccessible. (CVE-2013-4299, Moderate)

  - An off-by-one flaw was found in the way the ANSI CPRNG
    implementation in the Linux kernel processed non-block
    size aligned requests. This could lead to random numbers
    being generated with less bits of entropy than expected
    when ANSI CPRNG was used. (CVE-2013-4345, Moderate)

  - An information leak flaw was found in the way Xen
    hypervisor emulated the OUTS instruction for 64-bit
    paravirtualized guests. A privileged guest user could
    use this flaw to leak hypervisor stack memory to the
    guest. (CVE-2013-4368, Moderate)

This update also fixes the following bug :

  - A bug in the GFS2 code prevented glock work queues from
    freeing glock- related memory while the glock memory
    shrinker repeatedly queued a large number of demote
    requests, for example when performing a simultaneous
    backup of several live GFS2 volumes with a large file
    count. As a consequence, the glock work queues became
    overloaded which resulted in a high CPU usage and the
    GFS2 file systems being unresponsive for a significant
    amount of time. A patch has been applied to alleviate
    this problem by calling the yield() function after
    scheduling a certain amount of tasks on the glock work
    queues. The problem can now occur only with extremely
    high work loads.

The system must be rebooted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1310&L=scientific-linux-errata&T=0&P=2367
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?28c9bff8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/24");
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


flag = 0;
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-debuginfo-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-debuginfo-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debuginfo-common-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-debuginfo-2.6.18-371.1.2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-371.1.2.el5")) flag++;


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
