#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(106124);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-2579", "CVE-2018-2582", "CVE-2018-2588", "CVE-2018-2599", "CVE-2018-2602", "CVE-2018-2603", "CVE-2018-2618", "CVE-2018-2629", "CVE-2018-2633", "CVE-2018-2634", "CVE-2018-2637", "CVE-2018-2641", "CVE-2018-2663", "CVE-2018-2677", "CVE-2018-2678");

  script_name(english:"Scientific Linux Security Update : java-1.8.0-openjdk on SL6.x, SL7.x i386/x86_64 (20180117)");
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

  - Multiple flaws were found in the Hotspot and AWT
    components of OpenJDK. An untrusted Java application or
    applet could use these flaws to bypass certain Java
    sandbox restrictions. (CVE-2018-2582, CVE-2018-2641)

  - It was discovered that the LDAPCertStore class in the
    JNDI component of OpenJDK failed to securely handle LDAP
    referrals. An attacker could possibly use this flaw to
    make it fetch attacker controlled certificate data.
    (CVE-2018-2633)

  - The JGSS component of OpenJDK ignores the value of the
    javax.security.auth.useSubjectCredsOnly property when
    using HTTP/SPNEGO authentication and always uses global
    credentials. It was discovered that this could cause
    global credentials to be unexpectedly used by an
    untrusted Java application. (CVE-2018-2634)

  - It was discovered that the JMX component of OpenJDK
    failed to properly set the deserialization filter for
    the SingleEntryRegistry in certain cases. A remote
    attacker could possibly use this flaw to bypass intended
    deserialization restrictions. (CVE-2018-2637)

  - It was discovered that the LDAP component of OpenJDK
    failed to properly encode special characters in user
    names when adding them to an LDAP search query. A remote
    attacker could possibly use this flaw to manipulate LDAP
    queries performed by the LdapLoginModule class.
    (CVE-2018-2588)

  - It was discovered that the DNS client implementation in
    the JNDI component of OpenJDK did not use random source
    ports when sending out DNS queries. This could make it
    easier for a remote attacker to spoof responses to those
    queries. (CVE-2018-2599)

  - It was discovered that the I18n component of OpenJDK
    could use an untrusted search path when loading resource
    bundle classes. A local attacker could possibly use this
    flaw to execute arbitrary code as another local user by
    making their Java application load an attacker
    controlled class file. (CVE-2018-2602)

  - It was discovered that the Libraries component of
    OpenJDK failed to sufficiently limit the amount of
    memory allocated when reading DER encoded input. A
    remote attacker could possibly use this flaw to make a
    Java application use an excessive amount of memory if it
    parsed attacker supplied DER encoded input.
    (CVE-2018-2603)

  - It was discovered that the key agreement implementations
    in the JCE component of OpenJDK did not guarantee
    sufficient strength of used keys to adequately protect
    generated shared secret. This could make it easier to
    break data encryption by attacking key agreement rather
    than the encryption using the negotiated secret.
    (CVE-2018-2618)

  - It was discovered that the JGSS component of OpenJDK
    failed to properly handle GSS context in the native GSS
    library wrapper in certain cases. A remote attacker
    could possibly make a Java application using JGSS to use
    a previously freed context. (CVE-2018-2629)

  - It was discovered that multiple classes in the
    Libraries, AWT, and JNDI components of OpenJDK did not
    sufficiently validate input when creating object
    instances from the serialized form. A specially crafted
    input could cause a Java application to create objects
    with an inconsistent state or use an excessive amount of
    memory when deserialized. (CVE-2018-2663, CVE-2018-2677,
    CVE-2018-2678)

  - It was discovered that multiple encryption key classes
    in the Libraries component of OpenJDK did not properly
    synchronize access to their internal data. This could
    possibly cause a multi-threaded Java application to
    apply weak encryption to data because of the use of a
    key that was zeroed out. (CVE-2018-2579)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1801&L=scientific-linux-errata&F=&S=&P=6612
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?00b7937e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/18");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-1.8.0.161-3.b14.el6_9")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.8.0-openjdk-src-debug-1.8.0.161-3.b14.el6_9")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-debuginfo-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", reference:"java-1.8.0-openjdk-javadoc-zip-debug-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.161-0.b14.el7_4")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-debug-1.8.0.161-0.b14.el7_4")) flag++;


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
