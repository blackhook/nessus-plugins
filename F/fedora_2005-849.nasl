#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2005-849.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(19728);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"FEDORA", value:"2005-849");

  script_name(english:"Fedora Core 4 : httpd-2.0.54-10.2 (2005-849)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes two security fixes. An issue was discovered in
mod_ssl where 'SSLVerifyClient require' would not be honoured in
location context if the virtual host had 'SSLVerifyClient optional'
configured (CVE-2005-2700). An issue was discovered in memory
consumption of the byterange filter for dynamic resources such as PHP
or CGI script (CVE-2005-2728).

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2005-September/001342.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f70a26"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/17");
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
if (! ereg(pattern:"^4([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 4.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC4", reference:"httpd-2.0.54-10.2")) flag++;
if (rpm_check(release:"FC4", reference:"httpd-debuginfo-2.0.54-10.2")) flag++;
if (rpm_check(release:"FC4", reference:"httpd-devel-2.0.54-10.2")) flag++;
if (rpm_check(release:"FC4", reference:"httpd-manual-2.0.54-10.2")) flag++;
if (rpm_check(release:"FC4", reference:"mod_ssl-2.0.54-10.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / mod_ssl");
}
