#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-1087.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(20231);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2005-3186");
  script_xref(name:"FEDORA", value:"2005-1087");

  script_name(english:"Fedora Core 3 : gtk2-2.4.14-4.fc3.3 (2005-1087)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The gtk2 package contains the GIMP ToolKit (GTK+), a library for
creating graphical user interfaces for the X Window System.

A bug was found in the way gtk2 processes XPM images. An attacker
could create a carefully crafted XPM file in such a way that it could
cause an application linked with gtk2 to execute arbitrary code when
the file was opened by a victim. The Common Vulnerabilities and
Exposures project has assigned the name CVE-2005-3186 to this issue.

Ludwig Nussel discovered an infinite-loop denial of service bug in the
way gtk2 processes XPM images. An attacker could create a carefully
crafted XPM file in such a way that it could cause an application
linked with gtk2 to stop responding when the file was opened by a
victim. The Common Vulnerabilities and Exposures project has assigned
the name CVE-2005-2975 to this issue.

Users of gtk2 are advised to upgrade to these updated packages, which
contain backported patches and are not vulnerable to these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-November/001583.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?421d2b39"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected gtk2, gtk2-debuginfo and / or gtk2-devel packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtk2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/11/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"gtk2-2.4.14-4.fc3.3")) flag++;
if (rpm_check(release:"FC3", reference:"gtk2-debuginfo-2.4.14-4.fc3.3")) flag++;
if (rpm_check(release:"FC3", reference:"gtk2-devel-2.4.14-4.fc3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gtk2 / gtk2-debuginfo / gtk2-devel");
}
