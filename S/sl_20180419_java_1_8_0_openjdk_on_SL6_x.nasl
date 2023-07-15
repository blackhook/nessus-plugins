#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(109196);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-2790", "CVE-2018-2794", "CVE-2018-2795", "CVE-2018-2796", "CVE-2018-2797", "CVE-2018-2798", "CVE-2018-2799", "CVE-2018-2800", "CVE-2018-2814", "CVE-2018-2815");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL6.x i386/x86_64 (20180419)");
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
"Security Fix(es) :

  - OpenJDK: incorrect handling of Reference clones can lead
    to sandbox bypass (Hotspot, 8192025) (CVE-2018-2814)

  - OpenJDK: unrestricted deserialization of data from JCEKS
    key stores (Security, 8189997) (CVE-2018-2794)

  - OpenJDK: insufficient consistency checks in
    deserialization of multiple classes (Security, 8189977)
    (CVE-2018-2795)

  - OpenJDK: unbounded memory allocation during
    deserialization in PriorityBlockingQueue (Concurrency,
    8189981) (CVE-2018-2796)

  - OpenJDK: unbounded memory allocation during
    deserialization in TabularDataSupport (JMX, 8189985)
    (CVE-2018-2797)

  - OpenJDK: unbounded memory allocation during
    deserialization in Container (AWT, 8189989)
    (CVE-2018-2798)

  - OpenJDK: unbounded memory allocation during
    deserialization in NamedNodeMapImpl (JAXP, 8189993)
    (CVE-2018-2799)

  - OpenJDK: RMI HTTP transport enabled by default (RMI,
    8193833) (CVE-2018-2800)

  - OpenJDK: unbounded memory allocation during
    deserialization in StubIORImpl (Serialization, 8192757)
    (CVE-2018-2815)

  - OpenJDK: incorrect merging of sections in the JAR
    manifest (Security, 8189969) (CVE-2018-2790)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1804&L=scientific-linux-errata&F=&S=&P=1914
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?028f60a5"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk");
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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debug-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-1.8.0.171-3.b10.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.171-3.b10.el6_9")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-debug / etc");
}
