#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:1228 and 
# Oracle Linux Security Advisory ELSA-2015-1228 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(84784);
  script_version("2.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2015-2590",
    "CVE-2015-2601",
    "CVE-2015-2621",
    "CVE-2015-2625",
    "CVE-2015-2628",
    "CVE-2015-2632",
    "CVE-2015-2659",
    "CVE-2015-2808",
    "CVE-2015-3149",
    "CVE-2015-4000",
    "CVE-2015-4731",
    "CVE-2015-4732",
    "CVE-2015-4733",
    "CVE-2015-4748",
    "CVE-2015-4749",
    "CVE-2015-4760"
  );
  script_bugtraq_id(
    73684,
    74733,
    75784,
    75796,
    75812,
    75818,
    75823,
    75832,
    75854,
    75861,
    75867,
    75874,
    75877,
    75890,
    75895,
    75933
  );
  script_xref(name:"RHSA", value:"2015:1228");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Oracle Linux 6 / 7 : java-1.8.0-openjdk (ELSA-2015-1228) (Bar Mitzvah) (Logjam)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"From Red Hat Security Advisory 2015:1228 :

Updated java-1.8.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

Multiple flaws were discovered in the 2D, CORBA, JMX, Libraries and
RMI components in OpenJDK. An untrusted Java application or applet
could use these flaws to bypass Java sandbox restrictions.
(CVE-2015-4760, CVE-2015-2628, CVE-2015-4731, CVE-2015-2590,
CVE-2015-4732, CVE-2015-4733)

A flaw was found in the way the Libraries component of OpenJDK
verified Online Certificate Status Protocol (OCSP) responses. An OCSP
response with no nextUpdate date specified was incorrectly handled as
having unlimited validity, possibly causing a revoked X.509
certificate to be interpreted as valid. (CVE-2015-4748)

It was discovered that the JCE component in OpenJDK failed to use
constant time comparisons in multiple cases. An attacker could
possibly use these flaws to disclose sensitive information by
measuring the time used to perform operations using these non-constant
time comparisons. (CVE-2015-2601)

It was discovered that the GCM (Galois Counter Mode) implementation in
the Security component of OpenJDK failed to properly perform a null
check. This could cause the Java Virtual Machine to crash when an
application performed encryption using a block cipher in the GCM mode.
(CVE-2015-2659)

A flaw was found in the RC4 encryption algorithm. When using certain
keys for RC4 encryption, an attacker could obtain portions of the
plain text from the cipher text without the knowledge of the
encryption key. (CVE-2015-2808)

Note: With this update, OpenJDK now disables RC4 TLS/SSL cipher suites
by default to address the CVE-2015-2808 issue. Refer to Red Hat
Bugzilla bug 1207101, linked to in the References section, for
additional details about this change.

A flaw was found in the way the TLS protocol composed the
Diffie-Hellman (DH) key exchange. A man-in-the-middle attacker could
use this flaw to force the use of weak 512 bit export-grade keys
during the key exchange, allowing them do decrypt all traffic.
(CVE-2015-4000)

Note: This update forces the TLS/SSL client implementation in OpenJDK
to reject DH key sizes below 768 bits, which prevents sessions to be
downgraded to export-grade keys. Refer to Red Hat Bugzilla bug
1223211, linked to in the References section, for additional details
about this change.

It was discovered that the JNDI component in OpenJDK did not handle
DNS resolutions correctly. An attacker able to trigger such DNS errors
could cause a Java application using JNDI to consume memory and CPU
time, and possibly block further DNS resolution. (CVE-2015-4749)

Multiple information leak flaws were found in the JMX and 2D
components in OpenJDK. An untrusted Java application or applet could
use this flaw to bypass certain Java sandbox restrictions.
(CVE-2015-2621, CVE-2015-2632)

A flaw was found in the way the JSSE component in OpenJDK performed
X.509 certificate identity verification when establishing a TLS/SSL
connection to a host identified by an IP address. In certain cases,
the certificate was accepted as valid if it was issued for a host name
to which the IP address resolves rather than for the IP address.
(CVE-2015-2625)

Multiple insecure temporary file use issues were found in the way the
Hotspot component in OpenJDK created performance statistics and error
log files. A local attacker could possibly make a victim using OpenJDK
overwrite arbitrary files using a symlink attack. Note: This issue was
originally fixed as CVE-2015-0383, but the fix was regressed in the
RHSA-2015:0809 advisory. (CVE-2015-3149)

All users of java-1.8.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect.");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005198.html");
  script_set_attribute(attribute:"see_also", value:"https://oss.oracle.com/pipermail/el-errata/2015-July/005200.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected java-1.8.0-openjdk packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-4760");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2015-3149");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-1.8.0.51-0.b16.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-demo-1.8.0.51-0.b16.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-devel-1.8.0.51-0.b16.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-headless-1.8.0.51-0.b16.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.51-0.b16.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.8.0-openjdk-src-1.8.0.51-0.b16.el6_6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-1.8.0.51-1.b16.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-accessibility-1.8.0.51-1.b16.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-demo-1.8.0.51-1.b16.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-devel-1.8.0.51-1.b16.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-headless-1.8.0.51-1.b16.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-javadoc-1.8.0.51-1.b16.el7_1")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.8.0-openjdk-src-1.8.0.51-1.b16.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / etc");
}
