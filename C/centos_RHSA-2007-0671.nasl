#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0671 and 
# CentOS Errata and Security Advisory 2007:0671 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25908);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2007-1217", "CVE-2007-1353");
  script_xref(name:"RHSA", value:"2007:0671");

  script_name(english:"CentOS 3 : kernel (CESA-2007:0671)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated kernel packages that fix several security issues and bugs in
the Red Hat Enterprise Linux 3 kernel are now available.

This security advisory has been rated as having moderate security
impact by the Red Hat Security Response Team.

The Linux kernel handles the basic functions of the operating system.

These new kernel packages contain fixes for the security issues
described below :

* a flaw in the ISDN CAPI subsystem that allowed a remote user to
cause a denial of service or potential privilege escalation.
(CVE-2007-1217, Moderate)

* a flaw in the Bluetooth subsystem that allowed a local user to
trigger an information leak. (CVE-2007-1353, Low)

In addition to the security issues described above, fixes for the
following have been included :

* a race condition in the e1000 network driver that could cause ESB2
systems to be started without the RX unit being turned on.

* a related e1000 bug on ESB2 systems that could cause rlogin to fail.

Red Hat would like to thank Ilja van Sprundel for reporting an issue
fixed in this erratum.

Note: The kernel-unsupported package contains various drivers and
modules that are unsupported and therefore might contain security
problems that have not been addressed.

All Red Hat Enterprise Linux 3 users are advised to upgrade their
kernels to the packages associated with their machine architecture and
configurations as listed in this erratum."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014145.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2ce53e58"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014147.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?438a6b2d"
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-August/014148.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e9a189d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/08/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"CentOS-3", reference:"kernel-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-BOOT-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-doc-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"kernel-smp-unsupported-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"kernel-smp-unsupported-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-source-2.4.21-51.EL")) flag++;
if (rpm_check(release:"CentOS-3", reference:"kernel-unsupported-2.4.21-51.EL")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-BOOT / kernel-doc / kernel-hugemem / etc");
}
