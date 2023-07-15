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
  script_id(88407);
  script_version("2.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");

  script_name(english:"Scientific Linux Security Update : java-1.6.0-openjdk on SL5.x, SL6.x, SL7.x i386/x86_64 (20160126)");
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
"An out-of-bounds write flaw was found in the JPEG image format decoder
in the AWT component in OpenJDK. A specially crafted JPEG image could
cause a Java application to crash or, possibly execute arbitrary code.
An untrusted Java application or applet could use this flaw to bypass
Java sandbox restrictions. (CVE-2016-0483)

An integer signedness issue was found in the font parsing code in the
2D component in OpenJDK. A specially crafted font file could possibly
cause the Java Virtual Machine to execute arbitrary code, allowing an
untrusted Java application or applet to bypass Java sandbox
restrictions. (CVE-2016-0494)

It was discovered that the JAXP component in OpenJDK did not properly
enforce the totalEntitySizeLimit limit. An attacker able to make a
Java application process a specially crafted XML file could use this
flaw to make the application consume an excessive amount of memory.
(CVE-2016-0466)

Multiple flaws were discovered in the Networking and JMX components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2016-0402,
CVE-2016-0448)

Note: This update also disallows the use of the MD5 hash algorithm in
the certification path processing. The use of MD5 can be re-enabled by
removing MD5 from the jdk.certpath.disabledAlgorithms security
property defined in the java.security file.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1601&L=scientific-linux-errata&F=&S=&P=11744
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ca74feb3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-demo-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-devel-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.38-1.13.10.0.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.6.0-openjdk-src-1.6.0.38-1.13.10.0.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-demo-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-devel-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.38-1.13.10.0.el6_7")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.6.0-openjdk-src-1.6.0.38-1.13.10.0.el6_7")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-debuginfo-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.38-1.13.10.0.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.38-1.13.10.0.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-debuginfo / etc");
}
