#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2007-3130.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(28163);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2007-5197");
  script_bugtraq_id(26279);
  script_xref(name:"FEDORA", value:"2007-3130");

  script_name(english:"Fedora 7 : mono-1.2.3-5.fc7 (2007-3130)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow in the Mono.Math.BigInteger class in Mono allows
attackers to execute arbitrary code.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=367471"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.redhat.com/show_bug.cgi?id=367531"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2007-November/004653.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?08b2d68f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:bytefx-data-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ibm-data-db2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-oracle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-data-sybase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-locale-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-nunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-nunit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:mono-winforms");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/11/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2021 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 7.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC7", reference:"bytefx-data-mysql-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"ibm-data-db2-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-core-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-data-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-data-firebird-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-data-oracle-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-data-postgresql-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-data-sqlite-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-data-sybase-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-debuginfo-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-devel-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-extras-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-jscript-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-locale-extras-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-nunit-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-nunit-devel-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-web-1.2.3-5.fc7")) flag++;
if (rpm_check(release:"FC7", reference:"mono-winforms-1.2.3-5.fc7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bytefx-data-mysql / ibm-data-db2 / mono-core / mono-data / etc");
}
