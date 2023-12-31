#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-293.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(14691);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2004-0689");
  script_xref(name:"FEDORA", value:"2004-293");

  script_name(english:"Fedora Core 2 : kdebase-3.2.2-6.FC2 (2004-293)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andrew Tuitt reported that versions of KDE up to and including 3.2.3
create temporary directories with predictable names. A local attacker
could prevent KDE applications from functioning correctly, or
overwrite files owned by other users by creating malicious symlinks.
The Common Vulnerabilities and Exposures project has assigned the name
CVE-2004-0689 to this issue.

WESTPOINT internet reconnaissance services has discovered that the KDE
web browser Konqueror allows websites to set cookies for certain
country specific secondary top level domains. An attacker within one
of the affected domains could construct a cookie which would be sent
to all other websites within the domain leading to a session fixation
attack. This issue does not affect popular domains such as .co.uk,
.co.in, or .com. The Common Vulnerabilities and Exposures project has
assigned the name CVE-2004-0721 to this issue.

A frame injection spoofing vulnerability has been discovered in the
Konqueror web browser. This issue could allow a malicious website to
show arbitrary content in a named frame of a different browser window.
The Common Vulnerabilities and Exposures project has assigned the name
CVE-2004-0746 to this issue.

All users of KDE are advised to upgrade to these packages, which
contain backported patches from the KDE team for these issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-September/000285.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?85153fe0"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected kdebase, kdebase-debuginfo and / or kdebase-devel
packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kdebase-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:2");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/09");
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
if (rpm_check(release:"FC2", reference:"kdebase-3.2.2-6.FC2")) flag++;
if (rpm_check(release:"FC2", reference:"kdebase-debuginfo-3.2.2-6.FC2")) flag++;
if (rpm_check(release:"FC2", reference:"kdebase-devel-3.2.2-6.FC2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kdebase / kdebase-debuginfo / kdebase-devel");
}
