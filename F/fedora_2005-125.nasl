#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-125.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16354);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2005-125");

  script_name(english:"Fedora Core 2 : postgresql-7.4.7-1.FC2.2 (2005-125)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Feb 07 2005 Tom Lane <tgl at redhat.com>
    7.4.7-1.FC2.2

  - Put regression tests under /usr/lib64 on 64-bit archs,
    since .so files are not architecture-independent.

  - Mon Feb 07 2005 Tom Lane <tgl at redhat.com>
    7.4.7-1.FC2.1

  - Update to PostgreSQL 7.4.7 (fixes CVE-2005-0227 and
    other issues).

    - Update to PyGreSQL 3.6.1.

    - Add versionless symlinks to jar files (bz#145744)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-February/000682.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c946dbff"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-jdbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"postgresql-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-contrib-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-debuginfo-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-devel-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-docs-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-jdbc-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-libs-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-pl-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-python-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-server-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-tcl-7.4.7-1.FC2.2")) flag++;
if (rpm_check(release:"FC2", reference:"postgresql-test-7.4.7-1.FC2.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "postgresql / postgresql-contrib / postgresql-debuginfo / etc");
}
