#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2008-9458.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(34716);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2008-6552", "CVE-2008-6560");
  script_xref(name:"FEDORA", value:"2008-9458");

  script_name(english:"Fedora 9 : cman-2.03.09-1.fc9 / gfs2-utils-2.03.09-1.fc9 / rgmanager-2.03.09-1.fc9 (2008-9458)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A major code audit did show several unsecure use of /tmp. This update
addresses those issues across the whole code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=468966"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016030.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3e6a0e77"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016031.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0706c0b0"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2008-November/016032.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cbb33b3f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected cman, gfs2-utils and / or rgmanager packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(59, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:cman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gfs2-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rgmanager");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:9");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/11/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 9.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC9", reference:"cman-2.03.09-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"gfs2-utils-2.03.09-1.fc9")) flag++;
if (rpm_check(release:"FC9", reference:"rgmanager-2.03.09-1.fc9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cman / gfs2-utils / rgmanager");
}
