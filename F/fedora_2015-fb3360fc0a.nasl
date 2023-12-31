#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-fb3360fc0a.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89467);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2015-fb3360fc0a");

  script_name(english:"Fedora 21 : firefox-42.0-2.fc21 / nspr-4.10.10-1.fc21 / nss-3.20.1-1.0.fc21 / etc (2015-fb3360fc0a)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"firefox-42.0-2.fc22 - Update to 42.0 firefox-42.0-2.fc21 - Update to
42.0 firefox-42.0-2.fc23 - Update to 42.0 nspr-4.10.10-1.fc23 - Update
to NSPR_4_10_10_RTM nspr-4.10.10-1.fc21 - Update to NSPR_4_10_10_RTM
nspr-4.10.10-1.fc22 - Update to NSPR_4_10_10_RTM ----
firefox-41.0.2-2.fc21 - Update to 41.0.2 firefox-41.0.2-2.fc22 -
Update to 41.0.2 firefox-41.0.2-2.fc23 - Update to 41.0.2 ----
firefox-41.0-6.fc21

  - Rebuilt for old sqlite which is available in updates
    firefox-41.0-6.fc22 - Rebuilt for old sqlite which is
    available in updates firefox-41.0-6.fc23 - Rebuilt for
    old sqlite which is available in updates ----
    firefox-41.0-4.fc21 - New upstream 41.0
    firefox-41.0-4.fc22 - New upstream 41.0
    firefox-41.0-4.fc23 - New upstream 41.0 ----
    nss-3.20.0-1.1.1.fc21 - Enable ECC cipher-suites by
    default [hrbz#1185708] - Split the enabling patch in two
    for easier maintenance

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171239.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cd088bd4"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b202a836"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171241.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b6eb875a"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171242.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a05a6a3d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-November/171243.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6274de8d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-softokn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:nss-util");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^21([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 21.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC21", reference:"firefox-42.0-2.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"nspr-4.10.10-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"nss-3.20.1-1.0.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"nss-softokn-3.20.1-1.0.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"nss-util-3.20.1-1.0.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / nspr / nss / nss-softokn / nss-util");
}
