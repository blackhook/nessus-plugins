#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-169.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(13723);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2004-0414");
  script_xref(name:"FEDORA", value:"2004-169");

  script_name(english:"Fedora Core 1 : cvs-1.11.17-1 (2004-169)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"While investigating a previously fixed vulnerability, Derek Price
discovered a flaw relating to malformed 'Entry' lines which lead to a
missing NULL terminator. The Common Vulnerabilities and Exposures
project (cve.mitre.org) has assigned the name CVE-2004-0414 to this
issue.

Stefan Esser and Sebastian Krahmer conducted an audit of CVS and fixed
a number of issues that may have had security consequences.

Among the issues deemed likely to be exploitable were :

-- a double-free relating to the error_prog_name string
(CVE-2004-0416) -- an argument integer overflow (CVE-2004-0417) --
out-of-bounds writes in serv_notify (CVE-2004-0418).

An attacker who has access to a CVS server may be able to execute
arbitrary code under the UID on which the CVS server is executing.

Users of CVS are advised to upgrade to this updated package, which
updates the cvs package to version 1.11.17, which corrects these
issues.

Red Hat would like to thank Stefan Esser, Sebastian Krahmer, and Derek
Price for auditing, disclosing, and providing patches for these
issues.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-June/000165.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3b678517"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cvs and / or cvs-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cvs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/23");
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
if (! ereg(pattern:"^1([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 1.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC1", reference:"cvs-1.11.17-1")) flag++;
if (rpm_check(release:"FC1", reference:"cvs-debuginfo-1.11.17-1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cvs / cvs-debuginfo");
}
