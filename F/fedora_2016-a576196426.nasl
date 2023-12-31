#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2016-a576196426.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89589);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2016-a576196426");

  script_name(english:"Fedora 23 : owncloud-8.0.10-1.fc23 (2016-a576196426)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update provides the new upstream patch release of ownCloud
(7.0.12 for EPEL 6, 8.0.10 for all other distributions). It also adds
a 'well-known' redirect for WebDAV (alongside the existing ones for
CalDAV and CardDAV) - if you don't know what this is, don't worry.
These are bugfix updates which include fixes for some security
vulnerabilities rated 'low' and 'medium' by upstream. For full details
on the changes, see the [upstream
changelog](https://www.owncloud.org/changelog) and the security
advisories: [OC-
SA-2016-001](https://owncloud.org/security/advisory/?id=oc-sa-2016-001
), [OC-
SA-2016-002](https://owncloud.org/security/advisory/?id=oc-sa-2016-002
), [OC-
SA-2016-003](https://owncloud.org/security/advisory/?id=oc-sa-2016-003
), [OC-
SA-2016-004](https://owncloud.org/security/advisory/?id=oc-sa-2016-004
).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2016-January/176017.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?717b5f06"
  );
  # https://owncloud.org/security/advisory/?id=oc-sa-2016-001
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisories/"
  );
  # https://owncloud.org/security/advisory/?id=oc-sa-2016-002
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisories/"
  );
  # https://owncloud.org/security/advisory/?id=oc-sa-2016-003
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisories/"
  );
  # https://owncloud.org/security/advisory/?id=oc-sa-2016-004
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/security/advisories/"
  );
  # https://www.owncloud.org/changelog
  script_set_attribute(
    attribute:"see_also",
    value:"https://owncloud.org/changelog/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected owncloud package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:owncloud");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"owncloud-8.0.10-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "owncloud");
}
