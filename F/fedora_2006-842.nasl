#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2006-842.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24155);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2006-842");

  script_name(english:"Fedora Core 4 : ruby-1.8.4-3.fc4 (2006-842)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu Jul 20 2006 Akira TAGOH <tagoh at redhat.com> -
    1.8.4-3

    - security fixes [CVE-2006-3694]

    - ruby-1.8.4-fix-insecure-dir-operation.patch :

    - ruby-1.8.4-fix-insecure-regexp-modification.patch:
      fixed the insecure operations in the certain
      safe-level restrictions. (#199538)

  - ruby-1.8.4-fix-alias-safe-level.patch: fixed to not
    bypass the certain safe-level restrictions. (#199543)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2006-July/000446.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e1431471"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/17");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"irb-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"rdoc-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ri-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-debuginfo-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-devel-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-docs-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-libs-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-mode-1.8.4-3.fc4")) flag++;
if (rpm_check(release:"FC4", reference:"ruby-tcltk-1.8.4-3.fc4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "irb / rdoc / ri / ruby / ruby-debuginfo / ruby-devel / ruby-docs / etc");
}
