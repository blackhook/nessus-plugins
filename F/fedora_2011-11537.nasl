#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2011-11537.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56219);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2011-1148", "CVE-2011-1938", "CVE-2011-2202", "CVE-2011-2483", "CVE-2011-3182");
  script_bugtraq_id(46843, 47950, 48259, 49241, 49249);
  script_xref(name:"FEDORA", value:"2011-11537");

  script_name(english:"Fedora 14 : maniadrive-1.2-32.fc14 / php-5.3.8-1.fc14 / php-eaccelerator-0.9.6.1-9.fc14 (2011-11537)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security Enhancements and Fixes :

  - Updated crypt_blowfish to 1.2. (CVE-2011-2483)

    - Fixed crash in error_log(). Reported by Mateusz
      Kocielski

    - Fixed buffer overflow on overlog salt in crypt().

    - Fixed bug #54939 (File path injection vulnerability in
      RFC1867 File upload filename). Reported by Krzysztof
      Kotowicz. (CVE-2011-2202)

    - Fixed stack-based buffer overflow in socket_connect().
      (CVE-2011-1938)

    - Fixed bug #54238 (use-after-free in substr_replace()).
      (CVE-2011-1148)

Upstream announce for 5.3.8:
http://www.php.net/archive/2011.php#id2011-08-23-1 Upstream announce
for 5.3.7: http://www.php.net/archive/2011.php#id2011-08-18-1

Full Changelog: http://www.php.net/ChangeLog-5.php#5.3.8

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/ChangeLog-5.php#5.3.8"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/archive/2011.php#id2011-08-18-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.php.net/archive/2011.php#id2011-08-23-1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=688958"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=709067"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=713194"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=715025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=732516"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/066102.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4634af29"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/066103.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d7ceb4d"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2011-September/066104.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c8d9735d"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected maniadrive, php and / or php-eaccelerator
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:maniadrive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-eaccelerator");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:14");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^14([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 14.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC14", reference:"maniadrive-1.2-32.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"php-5.3.8-1.fc14")) flag++;
if (rpm_check(release:"FC14", reference:"php-eaccelerator-0.9.6.1-9.fc14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "maniadrive / php / php-eaccelerator");
}
