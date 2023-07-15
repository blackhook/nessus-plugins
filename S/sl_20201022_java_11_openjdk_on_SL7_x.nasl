#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(141842);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-14779", "CVE-2020-14781", "CVE-2020-14782", "CVE-2020-14792", "CVE-2020-14796", "CVE-2020-14797", "CVE-2020-14803");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Scientific Linux Security Update : java-11-openjdk on SL7.x x86_64 (20201022)");
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

  - OpenJDK: Credentials sent over unencrypted LDAP
    connection (JNDI, 8237990) (CVE-2020-14781)

  - OpenJDK: Certificate blacklist bypass via alternate
    certificate encodings (Libraries, 8237995)
    (CVE-2020-14782)

  - OpenJDK: Integer overflow leading to out-of-bounds
    access (Hotspot, 8241114) (CVE-2020-14792)

  - OpenJDK: Incomplete check for invalid characters in URI
    to path conversion (Libraries, 8242685) (CVE-2020-14797)

  - OpenJDK: Race condition in NIO Buffer boundary checks
    (Libraries, 8244136) (CVE-2020-14803)

  - OpenJDK: High memory usage during deserialization of
    Proxy class with many interfaces (Serialization,
    8236862) (CVE-2020-14779)

  - OpenJDK: Missing permission check in path to URI
    conversion (Libraries, 8242680) (CVE-2020-14796)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind2010&L=SCIENTIFIC-LINUX-ERRATA&P=26489
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a97904d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14792");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:java-11-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/23");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-debuginfo-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-demo-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-devel-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-headless-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-javadoc-zip-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-jmods-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-src-11.0.9.11-0.el7_9")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-11-openjdk-static-libs-11.0.9.11-0.el7_9")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-11-openjdk / java-11-openjdk-debuginfo / java-11-openjdk-demo / etc");
}
