#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1636 and 
# CentOS Errata and Security Advisory 2014:1636 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(79186);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2014-6457", "CVE-2014-6468", "CVE-2014-6502", "CVE-2014-6504", "CVE-2014-6506", "CVE-2014-6511", "CVE-2014-6512", "CVE-2014-6517", "CVE-2014-6519", "CVE-2014-6531", "CVE-2014-6558", "CVE-2014-6562");
  script_bugtraq_id(70488, 70523, 70533, 70538, 70544, 70548, 70552, 70556, 70564, 70567, 70570, 70572);
  script_xref(name:"RHSA", value:"2014:1636");

  script_name(english:"CentOS 6 : java-1.8.0-openjdk (CESA-2014:1636)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated java-1.8.0-openjdk packages that fix multiple security issues
are now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having Important
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The java-1.8.0-openjdk packages provide the OpenJDK 8 Java Runtime
Environment and the OpenJDK 8 Java Software Development Kit.

It was discovered that the Libraries component in OpenJDK failed to
properly handle ZIP archives that contain entries with a NUL byte used
in the file names. An untrusted Java application or applet could use
this flaw to bypass Java sandbox restrictions. (CVE-2014-6562)

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

It was discovered that the Hotspot component in OpenJDK failed to
properly handle malformed Shared Archive files. A local attacker able
to modify a Shared Archive file used by a virtual machine of a
different user could possibly use this flaw to escalate their
privileges. (CVE-2014-6468)

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

All users of java-1.8.0-openjdk are advised to upgrade to these
updated packages, which resolve these issues. All running instances of
OpenJDK Java must be restarted for the update to take effect."
  );
  # https://lists.centos.org/pipermail/centos-cr-announce/2014-October/001471.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a77da9a9"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected java-1.8.0-openjdk packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-6562");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 6.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-1.8.0.25-1.b17.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-demo-1.8.0.25-1.b17.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-devel-1.8.0.25-1.b17.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-headless-1.8.0.25-1.b17.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-javadoc-1.8.0.25-1.b17.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"java-1.8.0-openjdk-src-1.8.0.25-1.b17.el6")) flag++;


if (flag)
{
  cr_plugin_caveat = '\n' +
    'NOTE: The security advisory associated with this vulnerability has a\n' +
    'fixed package version that may only be available in the continuous\n' +
    'release (CR) repository for CentOS, until it is present in the next\n' +
    'point release of CentOS.\n\n' +

    'If an equal or higher package level does not exist in the baseline\n' +
    'repository for your major version of CentOS, then updates from the CR\n' +
    'repository will need to be applied in order to address the\n' +
    'vulnerability.\n';
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get() + cr_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "java-1.8.0-openjdk / java-1.8.0-openjdk-demo / etc");
}
