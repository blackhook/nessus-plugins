#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-822.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19724);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2005-822");

  script_name(english:"Fedora Core 4 : dbus-0.33-3.fc4.1 (2005-822)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Mon Aug 29 2005 John (J5) Palmieri <johnp at redhat.com>
    - 0.33-3.fc4.1

    - add patch from 0.2x series that fixes an exploit where
      users can attach to another user's session bus
      (CVE-2005-0201)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-August/001315.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97dd1ede"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"dbus-0.33-3.fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"dbus-debuginfo-0.33-3.fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"dbus-devel-0.33-3.fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"dbus-glib-0.33-3.fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"dbus-python-0.33-3.fc4.1")) flag++;
if (rpm_check(release:"FC4", reference:"dbus-x11-0.33-3.fc4.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dbus / dbus-debuginfo / dbus-devel / dbus-glib / dbus-python / etc");
}
