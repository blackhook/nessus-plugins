#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-cc585b503f.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(89410);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-5302");
  script_xref(name:"FEDORA", value:"2015-cc585b503f");

  script_name(english:"Fedora 23 : abrt-2.7.0-2.fc23 / libreport-2.6.3-1.fc23 (2015-cc585b503f)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2015-5302 abrt-2.7.0-2.fc23 - Fix broken problem
details in abrt-cli/gnome-abrt abrt-2.7.0-1.fc23 - cli-ng: initial -
bodhi: introduce wrapper for 'reporter-bugzilla -h' and 'abrt-bodhi' -
handle-event: remove obsolete workaround - remove 'not needed' code -
doc: change /var/tmp/abrt to /var/spool/abrt - doc: fix default
DumpLocation in abrt.conf man page - abrt- dump-xorg: support Xorg log
backtraces prefixed by (EE) - Resolves #1264739 libreport-2.6.3-1.fc23
- reporter-bugzilla: add parameter -p - fix save users changes after
reviewing dump dir files - bugzilla: don't attach build_ids - rewrite
event rule parser - ureport: improve curl's error messages - curl: add
posibility to use own Certificate Authority cert - Resolves #1270235,
CVE-2015-5302

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1270903"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-October/169996.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26cd8b67"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-October/169997.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4c474a97"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected abrt and / or libreport packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:abrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:libreport");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:23");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/31");
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
if (! ereg(pattern:"^23([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 23.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC23", reference:"abrt-2.7.0-2.fc23")) flag++;
if (rpm_check(release:"FC23", reference:"libreport-2.6.3-1.fc23")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "abrt / libreport");
}
