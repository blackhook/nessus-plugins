#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(106403);
  script_version("3.98");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2018-2579",
    "CVE-2018-2582",
    "CVE-2018-2588",
    "CVE-2018-2599",
    "CVE-2018-2602",
    "CVE-2018-2603",
    "CVE-2018-2618",
    "CVE-2018-2629",
    "CVE-2018-2633",
    "CVE-2018-2634",
    "CVE-2018-2637",
    "CVE-2018-2641",
    "CVE-2018-2663",
    "CVE-2018-2677",
    "CVE-2018-2678"
  );

  script_name(english:"EulerOS 2.0 SP2 : java-1.8.0-openjdk (EulerOS-SA-2018-1028)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the java-1.8.0-openjdk packages
installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Multiple flaws were found in the Hotspot and AWT
    components of OpenJDK. An untrusted Java application or
    applet could use these flaws to bypass certain Java
    sandbox restrictions. (CVE-2018-2582, CVE-2018-2641)

  - It was discovered that the LDAPCertStore class in the
    JNDI component of OpenJDK failed to securely handle
    LDAP referrals. An attacker could possibly use this
    flaw to make it fetch attacker controlled certificate
    data. (CVE-2018-2633)

  - The JGSS component of OpenJDK ignores the value of the
    javax.security.auth.useSubjectCredsOnly property when
    using HTTP/SPNEGO authentication and always uses global
    credentials. It was discovered that this could cause
    global credentials to be unexpectedly used by an
    untrusted Java application. (CVE-2018-2634)

  - It was discovered that the JMX component of OpenJDK
    failed to properly set the deserialization filter for
    the SingleEntryRegistry in certain cases. A remote
    attacker could possibly use this flaw to bypass
    intended deserialization restrictions. (CVE-2018-2637)

  - It was discovered that the LDAP component of OpenJDK
    failed to properly encode special characters in user
    names when adding them to an LDAP search query. A
    remote attacker could possibly use this flaw to
    manipulate LDAP queries performed by the
    LdapLoginModule class. (CVE-2018-2588)

  - It was discovered that the DNS client implementation in
    the JNDI component of OpenJDK did not use random source
    ports when sending out DNS queries. This could make it
    easier for a remote attacker to spoof responses to
    those queries. (CVE-2018-2599)

  - It was discovered that the I18n component of OpenJDK
    could use an untrusted search path when loading
    resource bundle classes. A local attacker could
    possibly use this flaw to execute arbitrary code as
    another local user by making their Java application
    load an attacker controlled class file. (CVE-2018-2602)

  - It was discovered that the Libraries component of
    OpenJDK failed to sufficiently limit the amount of
    memory allocated when reading DER encoded input. A
    remote attacker could possibly use this flaw to make a
    Java application use an excessive amount of memory if
    it parsed attacker supplied DER encoded input.
    (CVE-2018-2603)

  - It was discovered that the key agreement
    implementations in the JCE component of OpenJDK did not
    guarantee sufficient strength of used keys to
    adequately protect generated shared secret. This could
    make it easier to break data encryption by attacking
    key agreement rather than the encryption using the
    negotiated secret. (CVE-2018-2618)

  - It was discovered that the JGSS component of OpenJDK
    failed to properly handle GSS context in the native GSS
    library wrapper in certain cases. A remote attacker
    could possibly make a Java application using JGSS to
    use a previously freed context. (CVE-2018-2629)

  - It was discovered that multiple classes in the
    Libraries, AWT, and JNDI components of OpenJDK did not
    sufficiently validate input when creating object
    instances from the serialized form. A specially-crafted
    input could cause a Java application to create objects
    with an inconsistent state or use an excessive amount
    of memory when deserialized. (CVE-2018-2663,
    CVE-2018-2677, CVE-2018-2678)

  - It was discovered that multiple encryption key classes
    in the Libraries component of OpenJDK did not properly
    synchronize access to their internal data. This could
    possibly cause a multi-threaded Java application to
    apply weak encryption to data because of the use of a
    key that was zeroed out. (CVE-2018-2579)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2018-1028
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3be48844");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/01/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["java-1.8.0-openjdk-1.8.0.161-0.b14",
        "java-1.8.0-openjdk-devel-1.8.0.161-0.b14",
        "java-1.8.0-openjdk-headless-1.8.0.161-0.b14"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk");
}
