#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-019.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(24186);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2006-6870");
  script_xref(name:"FEDORA", value:"2007-019");

  script_name(english:"Fedora Core 6 : avahi-0.6.16-1.fc6 (2007-019)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update shoul fix CVE-2006-6870 reported in #221440.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-January/001249.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90a20239"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-compat-howl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-compat-libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-compat-libdns_sd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-glib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-qt3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-qt3-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-sharp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:avahi-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/15");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 6.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC6", reference:"avahi-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-compat-howl-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-compat-howl-devel-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-compat-libdns_sd-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-compat-libdns_sd-devel-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-debuginfo-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-devel-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-glib-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-glib-devel-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-qt3-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-qt3-devel-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-sharp-0.6.16-1.fc6")) flag++;
if (rpm_check(release:"FC6", reference:"avahi-tools-0.6.16-1.fc6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "avahi / avahi-compat-howl / avahi-compat-howl-devel / etc");
}
