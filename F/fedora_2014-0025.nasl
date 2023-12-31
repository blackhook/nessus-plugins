#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-0025.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(71913);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-6836");
  script_xref(name:"FEDORA", value:"2014-0025");

  script_name(english:"Fedora 18 : gnome-chemistry-utils-0.14.5-1.fc18 / gnumeric-1.12.9-1.fc18 / goffice-0.10.9-1.fc18 (2014-0025)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This is an update to the latest upstream releases of gnumeric, goffice
and gnome-chemistry-utils :

  -
    https://projects.gnome.org/gnumeric/announcements/1.12/g
    numeric-1.12.9.shtml

    -
      http://svn.savannah.nongnu.org/viewvc/*checkout*/branc
      hes/gchemutils-0.14/gchemutils/NEWS?revision=1856&root
      =gchemutils

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://svn.savannah.nongnu.org/viewvc/*checkout*/branches/gchemutils-0.14/gchemutils/NEWS?revision=1856&root=gchemutils
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1f16e82f"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1044858"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126299.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?084ea77c"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126300.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ec4605da"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-January/126301.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc138c3e"
  );
  # https://projects.gnome.org/gnumeric/announcements/1.12/gnumeric-1.12.9.shtml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2b90d512"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected gnome-chemistry-utils, gnumeric and / or goffice
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnome-chemistry-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gnumeric");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:goffice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:18");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^18([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 18.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC18", reference:"gnome-chemistry-utils-0.14.5-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"gnumeric-1.12.9-1.fc18")) flag++;
if (rpm_check(release:"FC18", reference:"goffice-0.10.9-1.fc18")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnome-chemistry-utils / gnumeric / goffice");
}
