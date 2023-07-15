#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2020-0912.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(134846);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2020-1938");
  script_xref(name:"RHSA", value:"2020:0912");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Oracle Linux 6 : tomcat6 (ELSA-2020-0912)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Description of changes:

[0:6.0.24-114]
- Related: rhbz#1806803 Update patch to remove secret attribute renaming

[0:6.0.24-113]
- Related: rhbz#1806803 Add IIS attributes to filter pattern and update 
secret logic

[0:6.0.24-112]
- Resolves: rhbz#1806803 CVE-2020-1938 tomcat6: tomcat: Apache Tomcat 
AJP File Read/Inclusion Vulnerability");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2020-March/009753.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected tomcat6 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-admin-webapps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-docs-webapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-el-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-jsp-2.1-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-servlet-2.5-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:tomcat6-webapps");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"tomcat6-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-admin-webapps-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-docs-webapp-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-el-2.1-api-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-javadoc-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-jsp-2.1-api-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-lib-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-servlet-2.5-api-6.0.24-114.el6_10")) flag++;
if (rpm_check(release:"EL6", reference:"tomcat6-webapps-6.0.24-114.el6_10")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tomcat6 / tomcat6-admin-webapps / tomcat6-docs-webapp / etc");
}
