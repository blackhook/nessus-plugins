#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77216);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3509", "CVE-2014-3510", "CVE-2014-3511");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x i386/x86_64 (20140813)");
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
"A race condition was found in the way OpenSSL handled ServerHello
messages with an included Supported EC Point Format extension. A
malicious server could possibly use this flaw to cause a
multi-threaded TLS/SSL client using OpenSSL to write into freed
memory, causing the client to crash or execute arbitrary code.
(CVE-2014-3509)

It was discovered that the OBJ_obj2txt() function could fail to
properly NUL-terminate its output. This could possibly cause an
application using OpenSSL functions to format fields of X.509
certificates to disclose portions of its memory. (CVE-2014-3508)

A flaw was found in the way OpenSSL handled fragmented handshake
packets. A man-in-the-middle attacker could use this flaw to force a
TLS/SSL server using OpenSSL to use TLS 1.0, even if both the client
and the server supported newer protocol versions. (CVE-2014-3511)

Multiple flaws were discovered in the way OpenSSL handled DTLS
packets. A remote attacker could use these flaws to cause a DTLS
server or client using OpenSSL to crash or use excessive amounts of
memory. (CVE-2014-3505, CVE-2014-3506, CVE-2014-3507)

A NULL pointer dereference flaw was found in the way OpenSSL performed
a handshake when using the anonymous Diffie-Hellman (DH) key exchange.
A malicious server could cause a DTLS client using OpenSSL to crash if
that client had anonymous DH cipher suites enabled. (CVE-2014-3510)

For the update to take effect, all services linked to the OpenSSL
library (such as httpd and other SSL-enabled services) must be
restarted or the system rebooted."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1408&L=scientific-linux-errata&T=0&P=942
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5d6f17d"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-16.el6_5.15")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-16.el6_5.15")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
