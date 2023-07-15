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
  script_id(88078);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-7575", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0475", "CVE-2016-0483", "CVE-2016-0494");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL7.x x86_64 (20160120) (SLOTH)");
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

It was discovered that the password-based encryption (PBE)
implementation in the Libraries component in OpenJDK used an incorrect
key length. This could, in certain cases, lead to generation of keys
that were weaker than expected. (CVE-2016-0475)

It was discovered that the JAXP component in OpenJDK did not properly
enforce the totalEntitySizeLimit limit. An attacker able to make a
Java application process a specially crafted XML file could use this
flaw to make the application consume an excessive amount of memory.
(CVE-2016-0466)

A flaw was found in the way TLS 1.2 could use the MD5 hash function
for signing ServerKeyExchange and Client Authentication packets during
a TLS handshake. A man-in-the-middle attacker able to force a TLS
connection to use the MD5 hash function could use this flaw to conduct
collision attacks to impersonate a TLS server or an authenticated TLS
client. (CVE-2015-7575)

Multiple flaws were discovered in the Networking and JMX components in
OpenJDK. An untrusted Java application or applet could use these flaws
to bypass certain Java sandbox restrictions. (CVE-2016-0402,
CVE-2016-0448)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

Note: This update also disallows the use of the MD5 hash algorithm in
the certification path processing. The use of MD5 can be re-enabled by
removing MD5 from the jdk.certpath.disabledAlgorithms security
property defined in the java.security file.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1601&L=scientific-linux-errata&F=&S=&P=10638
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5419e9be"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-accessibility-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.71-2.b15.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.71-2.b15.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
