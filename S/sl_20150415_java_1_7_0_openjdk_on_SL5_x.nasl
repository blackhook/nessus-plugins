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
  script_id(82814);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2005-1080", "CVE-2015-0460", "CVE-2015-0469", "CVE-2015-0477", "CVE-2015-0478", "CVE-2015-0480", "CVE-2015-0488");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL5.x i386/x86_64 (20150415)");
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
"An off-by-one flaw, leading to a buffer overflow, was found in the
font parsing code in the 2D component in OpenJDK. A specially crafted
font file could possibly cause the Java Virtual Machine to execute
arbitrary code, allowing an untrusted Java application or applet to
bypass Java sandbox restrictions. (CVE-2015-0469)

A flaw was found in the way the Hotspot component in OpenJDK handled
phantom references. An untrusted Java application or applet could use
this flaw to corrupt the Java Virtual Machine memory and, possibly,
execute arbitrary code, bypassing Java sandbox restrictions.
(CVE-2015-0460)

A flaw was found in the way the JSSE component in OpenJDK parsed X.509
certificate options. A specially crafted certificate could cause JSSE
to raise an exception, possibly causing an application using JSSE to
exit unexpectedly. (CVE-2015-0488)

A flaw was discovered in the Beans component in OpenJDK. An untrusted
Java application or applet could use this flaw to bypass certain Java
sandbox restrictions. (CVE-2015-0477)

A directory traversal flaw was found in the way the jar tool extracted
JAR archive files. A specially crafted JAR archive could cause jar to
overwrite arbitrary files writable by the user running jar when the
archive was extracted. (CVE-2005-1080, CVE-2015-0480)

It was found that the RSA implementation in the JCE component in
OpenJDK did not follow recommended practices for implementing RSA
signatures. (CVE-2015-0478)

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1504&L=scientific-linux-errata&T=0&P=1343
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?16789b07"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.7.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-demo-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-devel-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-javadoc-1.7.0.79-2.5.5.2.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"java-1.7.0-openjdk-src-1.7.0.79-2.5.5.2.el5_11")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.7.0-openjdk / java-1.7.0-openjdk-debuginfo / etc");
}
