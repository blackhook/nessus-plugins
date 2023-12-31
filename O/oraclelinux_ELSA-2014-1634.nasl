#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1634 and 
# Oracle Linux Security Advisory ELSA-2014-1634 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(78454);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-6457", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558");
  script_xref(name:"RHSA", value:"2014:1634");

  script_name(english:"Oracle Linux 5 / 6 / 7 : java-1.6.0-openjdk (ELSA-2014-1634)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:1634 :

Updated java-1.6.0-openjdk packages that fix multiple security issues
and one bug are now available for Red Hat Enterprise Linux 5, 6, and
7.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.6.0-openjdk packages provide the OpenJDK 6 Java Runtime
Environment and the OpenJDK 6 Java Software Development Kit.

Multiple flaws were discovered in the Libraries, 2D, and Hotspot
components in OpenJDK. An untrusted Java application or applet could
use these flaws to bypass certain Java sandbox restrictions.
(CVE-2014-6506, CVE-2014-6531, CVE-2014-6502, CVE-2014-6511,
CVE-2014-6504, CVE-2014-6519)

It was discovered that the StAX XML parser in the JAXP component in
OpenJDK performed expansion of external parameter entities even when
external entity substitution was disabled. A remote attacker could use
this flaw to perform XML eXternal Entity (XXE) attack against
applications using the StAX parser to parse untrusted XML documents.
(CVE-2014-6517)

It was discovered that the DatagramSocket implementation in OpenJDK
failed to perform source address checks for packets received on a
connected socket. A remote attacker could use this flaw to have their
packets processed as if they were received from the expected source.
(CVE-2014-6512)

It was discovered that the TLS/SSL implementation in the JSSE
component in OpenJDK failed to properly verify the server identity
during the renegotiation following session resumption, making it
possible for malicious TLS/SSL servers to perform a Triple Handshake
attack against clients using JSSE and client certificate
authentication. (CVE-2014-6457)

It was discovered that the CipherInputStream class implementation in
OpenJDK did not properly handle certain exceptions. This could
possibly allow an attacker to affect the integrity of an encrypted
stream handled by this class. (CVE-2014-6558)

The CVE-2014-6512 was discovered by Florian Weimer of Red Hat Product
Security.

This update also fixes the following bug :

* The TLS/SSL implementation in OpenJDK previously failed to handle
Diffie-Hellman (DH) keys with more than 1024 bits. This caused client
applications using JSSE to fail to establish TLS/SSL connections to
servers using larger DH keys during the connection handshake. This
update adds support for DH keys with size up to 2048 bits.
(BZ#1148309)

All users of java-1.6.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-October/004517.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-October/004522.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-October/004538.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.6.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.6.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

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
if (! preg(pattern:"^(5|6|7)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 5 / 6 / 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-1.6.0.33-1.13.5.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-demo-1.6.0.33-1.13.5.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-devel-1.6.0.33-1.13.5.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-javadoc-1.6.0.33-1.13.5.0.0.1.el5_11")) flag++;
if (rpm_check(release:"EL5", reference:"java-1.6.0-openjdk-src-1.6.0.33-1.13.5.0.0.1.el5_11")) flag++;

if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-1.6.0.33-1.13.5.0.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-demo-1.6.0.33-1.13.5.0.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-devel-1.6.0.33-1.13.5.0.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-javadoc-1.6.0.33-1.13.5.0.el6_6")) flag++;
if (rpm_check(release:"EL6", reference:"java-1.6.0-openjdk-src-1.6.0.33-1.13.5.0.el6_6")) flag++;

if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-1.6.0.33-1.13.5.0.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-demo-1.6.0.33-1.13.5.0.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-devel-1.6.0.33-1.13.5.0.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-javadoc-1.6.0.33-1.13.5.0.el7_0")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"java-1.6.0-openjdk-src-1.6.0.33-1.13.5.0.el7_0")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.6.0-openjdk / java-1.6.0-openjdk-demo / etc");
}
