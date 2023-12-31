#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2012-4451.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58693);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2012-1569");
  script_xref(name:"FEDORA", value:"2012-4451");

  script_name(english:"Fedora 17 : mingw-gnutls-2.12.17-1.fc17 / mingw-libtasn1-2.12-1.fc17 / mingw-p11-kit-0.12-1.fc17 (2012-4451)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a a DER decoding buffer overflow in the MinGW cross
compiled libtasn1 and gnutls packages. The mingw-gnutls build also
switches to using the system libtasn1 library instead of its bundled
copy.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=804920"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-April/077284.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ff3b25fb"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-April/077285.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4bb52203"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2012-April/077286.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8cbccc7e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected mingw-gnutls, mingw-libtasn1 and / or
mingw-p11-kit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mingw-p11-kit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:17");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^17([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 17.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC17", reference:"mingw-gnutls-2.12.17-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"mingw-libtasn1-2.12-1.fc17")) flag++;
if (rpm_check(release:"FC17", reference:"mingw-p11-kit-0.12-1.fc17")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mingw-gnutls / mingw-libtasn1 / mingw-p11-kit");
}
