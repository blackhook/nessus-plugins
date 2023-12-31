#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2014-349.
#

include("compat.inc");

if (description)
{
  script_id(78292);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2010-5298", "CVE-2014-0195", "CVE-2014-0198", "CVE-2014-0221", "CVE-2014-0224", "CVE-2014-3470", "CVE-2015-0292");
  script_xref(name:"ALAS", value:"2014-349");
  script_xref(name:"RHSA", value:"2014:0625");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2014-349)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that OpenSSL clients and servers could be forced, via a
specially crafted handshake packet, to use weak keying material for
communication. A man-in-the-middle attacker could use this flaw to
decrypt and modify traffic between a client and a server.
(CVE-2014-0224)

Note: In order to exploit this flaw, both the server and the client
must be using a vulnerable version of OpenSSL; the server must be
using OpenSSL version 1.0.1 and above, and the client must be using
any version of OpenSSL.

A buffer overflow flaw was found in the way OpenSSL handled invalid
DTLS packet fragments. A remote attacker could possibly use this flaw
to execute arbitrary code on a DTLS client or server. (CVE-2014-0195)

Multiple flaws were found in the way OpenSSL handled read and write
buffers when the SSL_MODE_RELEASE_BUFFERS mode was enabled. A TLS/SSL
client or server using OpenSSL could crash or unexpectedly drop
connections when processing certain SSL traffic. (CVE-2010-5298 ,
CVE-2014-0198)

A denial of service flaw was found in the way OpenSSL handled certain
DTLS ServerHello requests. A specially crafted DTLS handshake packet
could cause a DTLS client using OpenSSL to crash. (CVE-2014-0221)

A NULL pointer dereference flaw was found in the way OpenSSL performed
anonymous Elliptic Curve Diffie Hellman (ECDH) key exchange. A
specially crafted handshake packet could cause a TLS/SSL client that
has the anonymous ECDH cipher suite enabled to crash. (CVE-2014-3470)

An integer underflow flaw, leading to a heap-based buffer overflow,
was found in the way OpenSSL decoded certain base64 strings. A remote
attacker could provide a specially crafted base64 string via certain
PEM processing routines that, when parsed by the OpenSSL library,
would cause the OpenSSL server to crash. (CVE-2015-0292)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2014-349.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"openssl-1.0.1h-1.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.1h-1.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.1h-1.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.1h-1.72.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.1h-1.72.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
