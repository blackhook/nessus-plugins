#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-6907.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59007);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-0831", "CVE-2012-1172");
  script_bugtraq_id(53403);
  script_xref(name:"FEDORA", value:"2012-6907");

  script_name(english:"Fedora 16 : maniadrive-1.2-32.fc16.3 / php-5.3.11-1.fc16 / php-eaccelerator-0.9.6.1-9.fc16.3 (2012-6907)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream Security Enhancements :

  - Fixed bug #54374 (Insufficient validating of upload name
    leading to corrupted $_FILES indices). (CVE-2012-1172).

    - Add open_basedir checks to readline_write_history and
      readline_read_history.

    - Fixed bug #61043 (Regression in magic_quotes_gpc fix
      for CVE-2012-0831).

Upstream announce: http://www.php.net/archive/2012.php#id2012-04-26-1

RPM changes :

  - php-fpm: add comment about security.limit_extensions in
    provided conf

    - php-fpm: add /etc/sysconfig/php-fpm environment file

    - php-common provides zip extension, as in previous
      fedora version

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/archive/2012.php#id2012-04-26-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=789468"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=799187"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/080041.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3ca0cb5e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/080042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f92e740e"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-May/080043.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2707931a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maniadrive, php and / or php-eaccelerator
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:16");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^16([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 16.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC16", reference:"maniadrive-1.2-32.fc16.3")) flag++;
if (rpm_check(release:"FC16", reference:"php-5.3.11-1.fc16")) flag++;
if (rpm_check(release:"FC16", reference:"php-eaccelerator-0.9.6.1-9.fc16.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php / php-eaccelerator");
}
