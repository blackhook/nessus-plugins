#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-cf8ef2f333.
#

include("compat.inc");

if (description)
{
  script_id(140107);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/07");

  script_cve_id("CVE-2019-17566", "CVE-2019-17638");
  script_xref(name:"FEDORA", value:"2020-cf8ef2f333");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Fedora 32 : 1:ecj / 1:eclipse / 1:eclipse-emf / 2:eclipse-cdt / batik / etc (2020-cf8ef2f333)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Updates to the latest upstream release of Eclipse. See the upstream
release notes for details:
https://www.eclipse.org/eclipseide/2020-06/noteworthy/

Also contains security fixes for CVE-2019-17566 and CVE-2019-17638.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-cf8ef2f333"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:ecj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:eclipse-emf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:2:eclipse-cdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:batik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-ecf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-gef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-m2e-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-mpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-mylyn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:eclipse-webtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:jetty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:univocity-parsers");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"ecj-4.16-4.fc32", epoch:"1")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-4.16-11.fc32", epoch:"1")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-emf-2.22.0-2.fc32", epoch:"1")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-cdt-9.11.1-8.fc32", epoch:"2")) flag++;
if (rpm_check(release:"FC32", reference:"batik-1.13-1.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-ecf-3.14.8-4.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-gef-3.11.0-13.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-m2e-core-1.16.1-1.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-mpc-1.8.3-2.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-mylyn-3.25.0-3.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-remote-3.0.1-6.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"eclipse-webtools-3.18.0-4.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"jetty-9.4.31-2.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"lucene-8.4.1-9.fc32")) flag++;
if (rpm_check(release:"FC32", reference:"univocity-parsers-2.8.4-5.fc32")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:ecj / 1:eclipse / 1:eclipse-emf / 2:eclipse-cdt / batik / etc");
}
