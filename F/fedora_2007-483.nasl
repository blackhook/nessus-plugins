#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-483.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25128);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2007-483");

  script_name(english:"Fedora Core 5 : kernel-2.6.20-1.2316.fc5 (2007-483)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Linux kernel 2.6.20.7
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.7
Previous kernel had most of this update already applied.

Linux kernel 2.6.20.8
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.8 Fixes
CVE-2007-1861

Linux kernel 2.6.20.9
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.9 Fixes
CVE-2007-2242

Linux kernel 2.6.20.10
http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.10 Fixes
two bugs introduced by the two previous updates.

CVE-2007-1861: The netlink protocol has an infinite recursion bug that
allows users to cause a kernel crash.

CVE-2007-2242: The IPv6 protocol allows remote attackers to cause a
denial of service via crafted IPv6 type 0 route headers
(IPV6_RTHDR_TYPE_0) that create network amplification between two
routers.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.10
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5172e87"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b3c59b9"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.8
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?91256654"
  );
  # http://www.kernel.org/pub/linux/kernel/v2.6/ChangeLog-2.6.20.9
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d03cf455"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-May/001701.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21aaefb8"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-kdump-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-smp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xen0-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kernel-xenU-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 5.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC5", reference:"kernel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debug-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debug-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-debuginfo-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-doc-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-kdump-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-debug-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-debug-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", cpu:"i386", reference:"kernel-smp-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen0-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xen0-devel-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xenU-2.6.20-1.2316.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"kernel-xenU-devel-2.6.20-1.2316.fc5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debug / kernel-debug-devel / kernel-debuginfo / etc");
}
