#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-8943.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(55500);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-2515");
  script_xref(name:"FEDORA", value:"2011-8943");

  script_name(english:"Fedora 15 : PackageKit-0.6.15-2.fc15 (2011-8943)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - Upstream yum recently changed the behaviour when
    checking signatures on a package. The commit added a new
    configuration key which only affects local packages, but
    the key was set by default to False.

    - This meant that an end user could install a local
      unsigned rpm package using PackageKit without a GPG
      trust check, and the user would be told the untrusted
      package is itself trusted.

    - To exploit this low-impact vulnerability, a user would
      have to manually download an unsigned package file and
      would still be required to authenticate to install the
      package.

    - The CVE-ID for this bug is CVE-2011-2515

    - See https://bugzilla.redhat.com/show_bug.cgi?id=717566
      for details.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=717566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=718127"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-July/062253.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?20d2bb50"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected PackageKit package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:PackageKit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:15");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^15([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 15.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC15", reference:"PackageKit-0.6.15-2.fc15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "PackageKit");
}
