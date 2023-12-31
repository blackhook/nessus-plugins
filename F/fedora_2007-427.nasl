#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-427.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(25030);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2007-427");

  script_name(english:"Fedora Core 5 : libX11-1.0.0-4.fc5 (2007-427)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Fri Apr 6 2007 Adam Jackson <ajax at redhat.com> 1.0.0-4

    - libX11-CVE-2007-1667.patch: Fix CVE-2007-1667

    - Tue Jun 20 2006 Mike A. Harris <mharris at redhat.com>
      1.0.1-3.FC5.0

    - Added libX11-1.0.1-setuid.diff to fix potential
      security issue (#196094)

    - Change dependency on 'filesystem' package to
      'xorg-x11-filesystem' package, so we can control this
      dep centrally.

  - Added NEWS to doc list.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-April/001654.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16717b22"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected libX11, libX11-debuginfo and / or libX11-devel
packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (rpm_check(release:"FC5", reference:"libX11-1.0.0-4.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"libX11-debuginfo-1.0.0-4.fc5")) flag++;
if (rpm_check(release:"FC5", reference:"libX11-devel-1.0.0-4.fc5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11 / libX11-debuginfo / libX11-devel");
}
