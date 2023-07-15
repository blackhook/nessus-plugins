#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:294 and 
# CentOS Errata and Security Advisory 2005:294 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(21801);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2005-0757");
  script_xref(name:"RHSA", value:"2005:294");

  script_name(english:"CentOS 3 : kernel (CESA-2005:294)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages are now available as part of ongoing support
and maintenance of Red Hat Enterprise Linux version 3. This is the
fifth regular update.

The Linux kernel handles the basic functions of the operating system.

This is the fifth regular kernel update to Red Hat Enterprise Linux 3.

New features introduced by this update include :

  - support for 2-TB partitions on block devices - support
    for new disk, network, and USB devices - support for
    clustered APIC mode on AMD64 NUMA systems - netdump
    support on AMD64, Intel EM64T, Itanium, and ppc64
    systems - diskdump support on sym53c8xx and SATA
    piix/promise adapters - NMI switch support on AMD64 and
    Intel EM64T systems

There were many bug fixes in various parts of the kernel. The ongoing
effort to resolve these problems has resulted in a marked improvement
in the reliability and scalability of Red Hat Enterprise Linux 3.

Some key areas affected by these fixes include the kernel's
networking, SATA, TTY, and USB subsystems, as well as the
architecture-dependent handling under the ia64, ppc64, and x86_64
directories. Scalability improvements were made primarily in the
memory management and file system areas.

A flaw in offset handling in the xattr file system code backported to
Red Hat Enterprise Linux 3 was fixed. On 64-bit systems, a user who
can access an ext3 extended-attribute-enabled file system could cause
a denial of service (system crash). This issue is rated as having a
moderate security impact (CVE-2005-0757).

The following device drivers have been upgraded to new versions :

3c59x ------ LK1.1.18 3w-9xxx ---- 2.24.00.011fw (new in Update 5)
3w-xxxx ---- 1.02.00.037 8139too ---- (upstream 2.4.29) b44 --------
0.95 cciss ------ v2.4.54.RH1 e100 ------- 3.3.6-k2 e1000 ------
5.6.10.1-k2 lpfcdfc ---- 1.0.13 (new in Update 5) tg3 -------- 3.22RH

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architectures
and configurations as listed in this erratum."
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011711.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77a1a682"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011718.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6b2758d0"
  );
  # https://lists.centos.org/pipermail/centos-announce/2005-May/011719.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1411b328"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-BOOT");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-hugemem-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-smp-unsupported");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:kernel-unsupported");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 3.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-32.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-32.EL")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
}
