#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-434.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(15748);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2004-0914");
  script_xref(name:"FEDORA", value:"2004-434");

  script_name(english:"Fedora Core 3 : xorg-x11-6.8.1-12.FC3.1 (2004-434)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several integer overflow flaws in the X.Org libXpm library used to
decode XPM (X PixMap) images have been found and addressed. An
attacker could create a carefully crafted XPM file which would cause
an application to crash or potentially execute arbitrary code if
opened by a victim. The Common Vulnerabilities and Exposures project
(cve.mitre.org) has assigned the name CVE-2004-0914 to this issue.

Users are advised to upgrade to these erratum packages, which contain
backported security patches as well as other bug fixes.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-November/000403.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?fe2c0d32"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Mesa-libGLU");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-deprecated-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-deprecated-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-font-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-twm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xdm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:xorg-x11-xfs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:3");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/11/18");
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
if (! ereg(pattern:"^3([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 3.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC3", reference:"xorg-x11-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Mesa-libGL-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Mesa-libGLU-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Xdmx-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Xnest-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-Xvfb-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-deprecated-libs-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-deprecated-libs-devel-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-devel-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-doc-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-font-utils-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-libs-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-sdk-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-tools-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-twm-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-xauth-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-xdm-6.8.1-12.FC3.1")) flag++;
if (rpm_check(release:"FC3", reference:"xorg-x11-xfs-6.8.1-12.FC3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11 / xorg-x11-Mesa-libGL / xorg-x11-Mesa-libGLU / etc");
}
