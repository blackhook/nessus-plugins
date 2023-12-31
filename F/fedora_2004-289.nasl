#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-289.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14744);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2004-0753");
  script_xref(name:"FEDORA", value:"2004-289");

  script_name(english:"Fedora Core 2 : gtk2-2.4.7-2.4 (2004-289)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"During testing of a previously fixed flaw in Qt (CVE-2004-0691), a
flaw was discovered in the BMP image processor of gtk2. An attacker
could create a carefully crafted BMP file which would cause an
application to enter an infinite loop and not respond to user input
when the file was opened by a victim. The Common Vulnerabilities and
Exposures project (cve.mitre.org) has assigned the name CVE-2004-0753
to this issue.

During a security audit Chris Evans discovered a stack and a heap
overflow in the XPM image decoder. An attacker could create a
carefully crafted XPM file which could cause an application linked
with gtk2 to crash or possibly execute arbitrary code when the file
was opened by a victim. (CVE-2004-0782, CVE-2004-0783)

Chris Evans also discovered an integer overflow in the ICO image
decoder. An attacker could create a carefully crafted ICO file which
could cause an application linked with gtk2 to crash when the file was
opened by a victim. (CVE-2004-0788)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-September/000295.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7949bea8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gtk2, gtk2-debuginfo and / or gtk2-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^2([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 2.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC2", reference:"gtk2-2.4.7-2.4")) flag++;
if (rpm_check(release:"FC2", reference:"gtk2-debuginfo-2.4.7-2.4")) flag++;
if (rpm_check(release:"FC2", reference:"gtk2-devel-2.4.7-2.4")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk2 / gtk2-debuginfo / gtk2-devel");
}
