#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0220 and 
# CentOS Errata and Security Advisory 2007:0220 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(67041);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2006-3619");
  script_xref(name:"RHSA", value:"2007:0220");

  script_name(english:"CentOS 4 : gcc (CESA-2007:0220)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated gcc packages that fix a security issue and various bugs are
now available.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

The gcc packages include C, C++, Java, Fortran 77, Objective C, and
Ada 95 GNU compilers and related support libraries.

Jurgen Weigert discovered a directory traversal flaw in fastjar. An
attacker could create a malicious JAR file which, if unpacked using
fastjar, could write to any files the victim had write access to.
(CVE-2006-3619)

These updated packages also fix several bugs, including :

* two debug information generator bugs

* two internal compiler errors

In addition to this, protoize.1 and unprotoize.1 manual pages have
been added to the package and __cxa_get_exception_ptr@@CXXABI_1.3.1
symbol has been added into libstdc++.so.6.

For full details regarding all fixed bugs, refer to the package
changelog as well as the specified list of bug reports from bugzilla.

All users of gcc should upgrade to these updated packages, which
contain backported patches to resolve these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2007-May/013699.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2457cd65"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gcc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-g77");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libf2c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgcj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 4.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"cpp-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gcc-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gcc-c++-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gcc-g77-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gcc-gnat-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gcc-java-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"gcc-objc-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libf2c-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libgcc-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libgcj-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libgcj-devel-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libgnat-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libobjc-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libstdc++-3.4.6-8")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"libstdc++-devel-3.4.6-8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cpp / gcc / gcc-c++ / gcc-g77 / gcc-gnat / gcc-java / gcc-objc / etc");
}
