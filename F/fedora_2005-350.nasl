#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-350.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(62258);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2005-1046");
  script_xref(name:"FEDORA", value:"2005-350");

  script_name(english:"Fedora Core 3 : kdelibs-3.3.1-2.12.FC3 (2005-350)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow was found in the kimgio library for KDE 3.3.1. An
attacker could create a carefully crafted PCX image in such a way that
it would cause kimgio to execute arbitrary code when processing the
image. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2005-1046 to this issue.

All users of kdelibs should upgrade to these updated packages, which
contain a backported security patch to correct these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-May/000889.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5f15c817"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdelibs, kdelibs-debuginfo and / or kdelibs-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"kdelibs-3.3.1-2.12.FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kdelibs-debuginfo-3.3.1-2.12.FC3")) flag++;
if (rpm_check(release:"FC3", reference:"kdelibs-devel-3.3.1-2.12.FC3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdelibs / kdelibs-debuginfo / kdelibs-devel");
}
