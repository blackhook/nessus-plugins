#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2004-127.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(13702);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2004-0397");
  script_xref(name:"FEDORA", value:"2004-127");

  script_name(english:"Fedora Core 1 : subversion-0.32.1-2 (2004-127)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora Core host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stefan Esser discovered an issue in the date parsing routines in
Subversion which allows a buffer overflow. An attacker could send
malicious requests to a Subversion server (either Apache-based using
mod_dav_svn, or using the svnserve daemon) and perform arbitrary
execution of code. 

The Common Vulnerabilities and Exposures project (cve.mitre.org) has
assigned the name CVE-2004-0397 to this issue. This update includes
packages with a patch for this issue.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/announce/2004-May/000131.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?618b8f54"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Subversion Date Svnserve');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mod_dav_svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:subversion-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora_core:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/05/19");
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
if (rpm_check(release:"FC1", reference:"mod_dav_svn-0.32.1-2")) flag++;
if (rpm_check(release:"FC1", reference:"subversion-0.32.1-2")) flag++;
if (rpm_check(release:"FC1", reference:"subversion-debuginfo-0.32.1-2")) flag++;
if (rpm_check(release:"FC1", reference:"subversion-devel-0.32.1-2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mod_dav_svn / subversion / subversion-debuginfo / subversion-devel");
}
