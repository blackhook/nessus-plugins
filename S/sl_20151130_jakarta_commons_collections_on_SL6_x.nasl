#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87121);
  script_version("2.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-7501");

  script_name(english:"Scientific Linux Security Update : jakarta-commons-collections on SL6.x (noarch) (20151130)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that the Apache commons-collections library permitted
code execution when deserializing objects involving a specially
constructed chain of classes. A remote attacker could use this flaw to
execute arbitrary code with the permissions of the application using
the commons- collections library. (CVE-2015-7501)

With this update, deserialization of certain classes in the commons-
collections library is no longer allowed. Applications that require
those classes to be deserialized can use the system property
'org.apache.commons.collections.enableUnsafeSerialization' to
re-enable their deserialization.

In the interim, the quickest way to resolve this specific
deserialization vulnerability is to remove the vulnerable class files
(InvokerTransformer, InstantiateFactory, and InstantiateTransformer)
in all commons-collections jar files. Any manual changes should be
tested to avoid unforseen complications.

All running applications using the commons-collections library must be
restarted for the update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1511&L=scientific-linux-errata&F=&S=&P=17116
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b1bc1816"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jakarta-commons-collections");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jakarta-commons-collections-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jakarta-commons-collections-testframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jakarta-commons-collections-testframework-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:jakarta-commons-collections-tomcat5");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
os_ver = pregmatch(pattern: "Scientific Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Scientific Linux");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"jakarta-commons-collections-3.2.1-3.5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"jakarta-commons-collections-javadoc-3.2.1-3.5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"jakarta-commons-collections-testframework-3.2.1-3.5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"jakarta-commons-collections-testframework-javadoc-3.2.1-3.5.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"jakarta-commons-collections-tomcat5-3.2.1-3.5.el6_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jakarta-commons-collections / jakarta-commons-collections-javadoc / etc");
}
