#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory 2009-12229.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(43327);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2009-3555");
  script_bugtraq_id(36935);
  script_xref(name:"FEDORA", value:"2009-12229");

  script_name(english:"Fedora 12 : tomcat-native-1.1.18-1.fc12 (2009-12229)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Update to 1.1.18, implementing a mitigation for CVE-2009-3555.
http://tomcat.apache.org/native-doc/miscellaneous/changelog-1.1.x.html
http://marc.info/?l=tomcat-dev&m=125900987921402&w=2
http://marc.info/?l =tomcat-dev&m=125874793414940&w=2
http://marc.info/?l=tomcat- user&m=125874793614950&w=2

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://marc.info/?l
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l"
  );
  # http://marc.info/?l=tomcat-
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=tomcat-"
  );
  # http://marc.info/?l=tomcat-dev&m=125900987921402&w=2
  script_set_attribute(
    attribute:"see_also",
    value:"https://marc.info/?l=tomcat-dev&m=125900987921402&w=2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://tomcat.apache.org/native-doc/miscellaneous/changelog-1.1.x.html"
  );
  # https://lists.fedoraproject.org/pipermail/package-announce/2009-December/032838.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eb03b77e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected tomcat-native package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:tomcat-native");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:12");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! ereg(pattern:"^12([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 12.x", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);

flag = 0;
if (rpm_check(release:"FC12", reference:"tomcat-native-1.1.18-1.fc12")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat-native");
}
