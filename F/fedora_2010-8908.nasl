#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2010-8908.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(47516);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2010-1512");
  script_xref(name:"FEDORA", value:"2010-8908");

  script_name(english:"Fedora 12 : aria2-1.9.3-1.fc12 (2010-8908)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Thu May 20 2010 Rahul Sundaram <sundaram at
    fedoraproject.org> - 1.9.3-1

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=2101

    - Fixes CVE-2010-1512. rhbz # 592014

    - Sat Mar 20 2010 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.9.0-1

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1990

    - Tue Feb 16 2010 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.8.2-1

    - Several bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1860

    - Mon Dec 28 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.8.0-1

    - Many new features including XML RPC improvements and
      other bug fixes

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1778

    - Mon Dec 7 2009 Rahul Sundaram <sundaram at
      fedoraproject.org> - 1.7.1-1

    - Option --bt-prioritize-piece=tail will work again

    -
      http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NE
      WS?revision=1721

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1860"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=1990"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://aria2.svn.sourceforge.net/viewvc/aria2/trunk/NEWS?revision=2101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=592012"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2010-May/041754.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5c3a8c2"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected aria2 package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:aria2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"aria2-1.9.3-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "aria2");
}
