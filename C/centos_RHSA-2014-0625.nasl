#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:0625 and 
# CentOS Errata and Security Advisory 2014:0625 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(74334);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470");
  script_bugtraq_id(66801, 67193, 67898, 67899, 67900, 67901);
  script_xref(name:"RHSA", value:"2014:0625");

  script_name(english:"CentOS 6 : openssl (CESA-2014:0625)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated openssl packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6.

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
  # https://lists.centos.org/pipermail/centos-announce/2014-June/020344.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?78319e9a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssl packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0195");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/06");
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
if (rpm_check(release:"CentOS-6", reference:"openssl-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-devel-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-perl-1.0.1e-16.el6_5.14")) flag++;
if (rpm_check(release:"CentOS-6", reference:"openssl-static-1.0.1e-16.el6_5.14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-devel / openssl-perl / openssl-static");
}
