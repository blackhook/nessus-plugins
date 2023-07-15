#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(133194);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2020-2583", "CVE-2020-2590", "CVE-2020-2593", "CVE-2020-2601", "CVE-2020-2604", "CVE-2020-2654", "CVE-2020-2659");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL7.x x86_64 (20200122)");
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

  - OpenJDK: Use of unsafe RSA-MD5 checkum in Kerberos TGS
    (Security, 8229951) (CVE-2020-2601)

  - OpenJDK: Serialization filter changes via
    jdk.serialFilter property modification (Serialization,
    8231422) (CVE-2020-2604)

  - OpenJDK: Improper checks of SASL message properties in
    GssKrb5Base (Security, 8226352) (CVE-2020-2590)

  - OpenJDK: Incorrect isBuiltinStreamHandler causing URL
    normalization issues (Networking, 8228548)
    (CVE-2020-2593)

  - OpenJDK: Excessive memory usage in OID processing in
    X.509 certificate parsing (Libraries, 8234037)
    (CVE-2020-2654)

  - OpenJDK: Incorrect exception processing during
    deserialization in BeanContextSupport (Serialization,
    8224909) (CVE-2020-2583)

  - OpenJDK: Incomplete enforcement of maxDatagramSockets
    limit in DatagramChannelImpl (Networking, 8231795)
    (CVE-2020-2659)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2001&L=SCIENTIFIC-LINUX-ERRATA&P=5367
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?123393e9"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2604");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-1.8.0-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.242.b08-0.el7_7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.242.b08-0.el7_7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
