#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2015-13488.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85669);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2015-5161");
  script_xref(name:"FEDORA", value:"2015-13488");

  script_name(english:"Fedora 21 : php-ZendFramework2-2.4.7-1.fc21 / php-guzzle-Guzzle-3.9.3-5.fc21 (2015-13488)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Zend Framework Upstream ChangeLogs: * [Version
2.4.7](http://framework.zend.com/changelog/2.4.7/) * [Version
2.4.6](http://framework.zend.com/changelog/2.4.6/) * [Version
2.4.5](http://framework.zend.com/changelog/2.4.5/) * [Version
2.4.4](http://framework.zend.com/changelog/2.4.4/) * [Version
2.4.3](http://framework.zend.com/changelog/2.4.3/) * [Version
2.4.2](http://framework.zend.com/changelog/2.4.2/) * [Version
2.4.1](http://framework.zend.com/changelog/2.4.1/) * [Version
2.4.0](http://framework.zend.com/changelog/2.4.0/)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://framework.zend.com/changelog/2.4.0/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.0/"
  );
  # http://framework.zend.com/changelog/2.4.1/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.1/"
  );
  # http://framework.zend.com/changelog/2.4.2/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.2/"
  );
  # http://framework.zend.com/changelog/2.4.3/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.3/"
  );
  # http://framework.zend.com/changelog/2.4.4/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.4/"
  );
  # http://framework.zend.com/changelog/2.4.5/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.5/"
  );
  # http://framework.zend.com/changelog/2.4.6/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.6/"
  );
  # http://framework.zend.com/changelog/2.4.7/
  script_set_attribute(
    attribute:"see_also",
    value:"https://framework.zend.com/changelog/2.4.7/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=1253250"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-August/165173.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a20ec5a9"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2015-August/165174.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1c02c514"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected php-ZendFramework2 and / or php-guzzle-Guzzle
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-ZendFramework2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-guzzle-Guzzle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC21", reference:"php-ZendFramework2-2.4.7-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"php-guzzle-Guzzle-3.9.3-5.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-ZendFramework2 / php-guzzle-Guzzle");
}
