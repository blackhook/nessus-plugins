#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2014-17341.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80298);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(71732);
  script_xref(name:"FEDORA", value:"2014-17341");

  script_name(english:"Fedora 21 : eclipse-egit-3.5.3-1.fc21 / eclipse-jgit-3.5.3-1.fc21 (2014-17341)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Fixes for CVE-2014-9390

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/147192.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d40e2840"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2014-December/147193.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b671553c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected eclipse-egit and / or eclipse-jgit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-egit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-jgit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:21");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"FC21", reference:"eclipse-egit-3.5.3-1.fc21")) flag++;
if (rpm_check(release:"FC21", reference:"eclipse-jgit-3.5.3-1.fc21")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "eclipse-egit / eclipse-jgit");
}
