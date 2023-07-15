#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2018-1016.
#

include("compat.inc");

if (description)
{
  script_id(109698);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/10 16:04:12");

  script_cve_id("CVE-2017-3736", "CVE-2017-3737", "CVE-2017-3738");
  script_xref(name:"ALAS", value:"2018-1016");

  script_name(english:"Amazon Linux AMI : openssl (ALAS-2018-1016)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"There is an overflow bug in the AVX2 Montgomery multiplication
procedure used in exponentiation with 1024-bit moduli. No EC
algorithms are affected. Analysis suggests that attacks against RSA
and DSA as a result of this defect would be very difficult to perform
and are not believed likely. Attacks against DH1024 are considered
just feasible, because most of the work necessary to deduce
information about a private key may be performed offline. The amount
of resources required for such an attack would be significant.
However, for an attack on TLS to be meaningful, the server would have
to share the DH1024 private key among multiple clients, which is no
longer an option since CVE-2016-0701 . This only affects processors
that support the AVX2 but not ADX extensions like Intel Haswell (4th
generation). Note: The impact from this issue is similar to
CVE-2017-3736 , CVE-2017-3732 and CVE-2015-3193 . OpenSSL version
1.0.2-1.0.2m and 1.1.0-1.1.0g are affected. Fixed in OpenSSL 1.0.2n.
Due to the low severity of this issue we are not issuing a new release
of OpenSSL 1.1.0 at this time. The fix will be included in OpenSSL
1.1.0h when it becomes available. The fix is also available in commit
e502cc86d in the OpenSSL git repository.(CVE-2017-3738)

OpenSSL 1.0.2 (starting from version 1.0.2b) introduced an 'error
state' mechanism. The intent was that if a fatal error occurred during
a handshake then OpenSSL would move into the error state and would
immediately fail if you attempted to continue the handshake. This
works as designed for the explicit handshake functions
(SSL_do_handshake(), SSL_accept() and SSL_connect()), however due to a
bug it does not work correctly if SSL_read() or SSL_write() is called
directly. In that scenario, if the handshake fails then a fatal error
will be returned in the initial function call. If
SSL_read()/SSL_write() is subsequently called by the application for
the same SSL object then it will succeed and the data is passed
without being decrypted/encrypted directly from the SSL/TLS record
layer. In order to exploit this issue an application bug would have to
be present that resulted in a call to SSL_read()/SSL_write() being
issued after having already received a fatal error. OpenSSL version
1.0.2b-1.0.2m are affected. Fixed in OpenSSL 1.0.2n. OpenSSL 1.1.0 is
not affected.(CVE-2017-3737)

There is a carry propagating bug in the x86_64 Montgomery squaring
procedure in OpenSSL before 1.0.2m and 1.1.0 before 1.1.0g. No EC
algorithms are affected. Analysis suggests that attacks against RSA
and DSA as a result of this defect would be very difficult to perform
and are not believed likely. Attacks against DH are considered just
feasible (although very difficult) because most of the work necessary
to deduce information about a private key may be performed offline.
The amount of resources required for such an attack would be very
significant and likely only accessible to a limited number of
attackers. An attacker would additionally need online access to an
unpatched system using the target private key in a scenario with
persistent DH parameters and a private key that is shared between
multiple clients. This only affects processors that support the BMI1,
BMI2 and ADX extensions like Intel Broadwell (5th generation) and
later or AMD Ryzen.(CVE-2017-3736)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2018-1016.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update openssl' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"ALA", reference:"openssl-1.0.2k-12.109.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-debuginfo-1.0.2k-12.109.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-devel-1.0.2k-12.109.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-perl-1.0.2k-12.109.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"openssl-static-1.0.2k-12.109.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
