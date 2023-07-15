#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-1384.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(30239);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-0553");
  script_xref(name:"FEDORA", value:"2008-1384");

  script_name(english:"Fedora 7 : perl-Tk-804.028-3.fc7 (2008-1384)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Tue Feb 5 2008 Andreas Bierfert
    <andreas.bierfert[AT]lowlatency.de>

    - 804.028-3

    - fix #431529 gif overflow in tk (see also #431518)

    - Fri Jan 4 2008 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 804.028-2

    - add relevant parts of debian patch

    - add patch for #235666

    - Wed Jan 2 2008 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 804.028-1

    - version upgrade

    - fix #210718 SIGSEGV on exit from texdoctk

    - fix #234404 Cannot manage big listboxes

    - fix #235666 Segfault occurs when using Perl-Tk on FC6

    - Wed Dec 19 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 804.027-13

    - fix BR

    - Wed Aug 22 2007 Andreas Bierfert
      <andreas.bierfert[AT]lowlatency.de>

    - 804.027-12

    - rebuild for buildid

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=431518"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-February/007586.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?37c8b074"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected perl-Tk package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Tk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"perl-Tk-804.028-3.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-Tk");
}