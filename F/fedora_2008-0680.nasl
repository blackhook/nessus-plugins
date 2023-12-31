#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-0680.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(31361);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-6703", "CVE-2008-1136");
  script_bugtraq_id(28141);
  script_xref(name:"FEDORA", value:"2008-0680");

  script_name(english:"Fedora 8 : librapi-0.11-1.fc8 / librra-0.11-1.fc8 / libsynce-0.11-2.fc8 / odccm-0.11-1.fc8 / etc (2008-0680)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Fedora host is missing one or more security updates :

librra-0.11-1.fc8 :

  - Wed Jan 9 2008 Andreas Bierfert
    <andreas.bierfert[AT]lowlatency.de>

    - 0.11-1

    - version upgrade

    - Fri Dec 21 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 0.10.0-2

    - rework BR

    - Wed May 9 2007 Aurelien Bompard <abompard at
      fedoraproject.org> 0.10.0-1

    - version 0.10.0

synce-serial-0.11-1.fc8 :

  - Wed Jan 9 2008 Andreas Bierfert
    <andreas.bierfert[AT]lowlatency.de>

    - 0.11-1

    - version upgrade

    - remove dependency on vdccm

    - Fri Dec 21 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - correct Requires

    - fix #249031 udev rule

    - Wed May 9 2007 Aurelien Bompard <abompard at
      fedoraproject.org> 0.10.0-1

    - version 0.10.0

librapi-0.11-1.fc8 / libsynce-0.11-2.fc8 / odccm-0.11-1.fc8 /
pywbxml-0.1-2.fc8 / synce-gnome-0.11-2.fc8 / synce-kpm-0.11-3.fc8 /
synce-sync-engine-0.11-6.fc8 / vdccm-0.10.1-1.fc8 :

  - Bug #436023 - CVE-2007-6703 vdccm 0.10.1 fixes a
    security vulnerability

  - Bug #436024 - CVE-2008-1136 vdccm insufficient escaping
    of shell metacharacters

wbxml2-0.9.2-12.fc8 :

  - Sat Jan 12 2008 Andreas Bierfert
    <andreas.bierfert[AT]lowlatency.de>

    - 0.9.2-12

    - pkgconfig also needs libxml2-devel

    - Sat Jan 12 2008 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 0.9.2-11

    - fix devel requires

    - Mon Jan 7 2008 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 0.9.2-10

    - add synce patches

synce-gnomevfs-0.11-1.fc8 :

  - Wed Jan 9 2008 Andreas Bierfert
    <andreas.bierfert[AT]lowlatency.de>

    - 0.11-1

    - version upgrade

    - Sun Dec 23 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 0.10.0-1

    - version upgrade

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=436023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=436024"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008468.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ce10b648"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008469.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?57977440"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008470.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4e621654"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008471.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ea2d8d86"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008472.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bdbfd06b"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008473.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ad76168a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008474.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?27681e96"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008475.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?541d9357"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008476.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74aa5c19"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008477.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e06e10ea"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008478.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f16ba58e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-March/008479.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?923abeb6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(20, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:librapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:librra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libsynce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:odccm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pywbxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synce-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synce-gnomevfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synce-kpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synce-serial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synce-sync-engine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:vdccm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:wbxml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/03/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 8.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC8", reference:"librapi-0.11-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"librra-0.11-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"libsynce-0.11-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"odccm-0.11-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"pywbxml-0.1-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"synce-gnome-0.11-2.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"synce-gnomevfs-0.11-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"synce-kpm-0.11-3.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"synce-serial-0.11-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"synce-sync-engine-0.11-6.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"vdccm-0.10.1-1.fc8")) flag++;
if (rpm_check(release:"FC8", reference:"wbxml2-0.9.2-12.fc8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "librapi / librra / libsynce / odccm / pywbxml / synce-gnome / etc");
}
