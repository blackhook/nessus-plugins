#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:0679 and 
# Oracle Linux Security Advisory ELSA-2014-0679 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(76729);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(66801, 67193, 67898, 67899, 67900, 67901);
  script_xref(name:"RHSA", value:"2014:0679");

  script_name(english:"Oracle Linux 7 : openssl (ELSA-2014-0679)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2014:0679 :

Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 7.

The Red Hat Security Response Team has rated this update as having
Important security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

It was found that OpenSSL clients and servers could be forced, via a
specially crafted handshake packet, to use weak keying material for
communication. A man-in-the-middle attacker could use this flaw to
decrypt and modify traffic between a client and a server.
(CVE-2014-0224)

Note: In order to exploit this flaw, both the server and the client
must be using a vulnerable version of OpenSSL; the server must be
using OpenSSL version 1.0.1 and above, and the client must be using
any version of OpenSSL. For more information about this flaw, refer
to: https://access.redhat.com/site/articles/904433

A buffer overflow flaw was found in the way OpenSSL handled invalid
DTLS packet fragments. A remote attacker could possibly use this flaw
to execute arbitrary code on a DTLS client or server. (CVE-2014-0195)

Multiple flaws were found in the way OpenSSL handled read and write
buffers when the SSL_MODE_RELEASE_BUFFERS mode was enabled. A TLS/SSL
client or server using OpenSSL could crash or unexpectedly drop
connections when processing certain SSL traffic. (CVE-2010-5298,
CVE-2014-0198)

A denial of service flaw was found in the way OpenSSL handled certain
DTLS ServerHello requests. A specially crafted DTLS handshake packet
could cause a DTLS client using OpenSSL to crash. (CVE-2014-0221)

A NULL pointer dereference flaw was found in the way OpenSSL performed
anonymous Elliptic Curve Diffie Hellman (ECDH) key exchange. A
specially crafted handshake packet could cause a TLS/SSL client that
has the anonymous ECDH cipher suite enabled to crash. (CVE-2014-3470)

Red Hat would like to thank the OpenSSL project for reporting these
issues. Upstream acknowledges KIKUCHI Masashi of Lepidum as the
original reporter of CVE-2014-0224, Juri Aedla as the original
reporter of CVE-2014-0195, Imre Rad of Search-Lab as the original
reporter of CVE-2014-0221, and Felix Grobert and Ivan Fratric of
Google as the original reporters of CVE-2014-3470.

All OpenSSL users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all services linked to the OpenSSL library
(such as httpd and other SSL-enabled services) must be restarted or
the system rebooted."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2014-July/004272.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/24");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 7", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-1.0.1e-34.el7_0.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-devel-1.0.1e-34.el7_0.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-libs-1.0.1e-34.el7_0.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-perl-1.0.1e-34.el7_0.3")) flag++;
if (rpm_check(release:"EL7", cpu:"x86_64", reference:"openssl-static-1.0.1e-34.el7_0.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-libs / openssl-perl / etc");
}
