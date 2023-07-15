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
  script_id(61290);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-4128", "CVE-2012-1569", "CVE-2012-1573");

  script_name(english:"Scientific Linux Security Update : gnutls on SL5.x i386/x86_64 (20120327)");
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
"The GnuTLS library provides support for cryptographic algorithms and
for protocols such as Transport Layer Security (TLS). GnuTLS includes
libtasn1, a library developed for ASN.1 (Abstract Syntax Notation One)
structures management that includes DER (Distinguished Encoding Rules)
encoding and decoding.

A flaw was found in the way GnuTLS decrypted malformed TLS records.
This could cause a TLS/SSL client or server to crash when processing a
specially crafted TLS record from a remote TLS/SSL connection peer.
(CVE-2012-1573)

A flaw was found in the way libtasn1 decoded DER data. An attacker
could create a carefully-crafted X.509 certificate that, when parsed
by an application that uses GnuTLS, could cause the application to
crash. (CVE-2012-1569)

A boundary error was found in the gnutls_session_get_data() function.
A malicious TLS/SSL server could use this flaw to crash a TLS/SSL
client or, possibly, execute arbitrary code as the client, if the
client passed a fixed-sized buffer to gnutls_session_get_data() before
checking the real size of the session data provided by the server.
(CVE-2011-4128)

Users of GnuTLS are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. For the
update to take effect, all applications linked to the GnuTLS library
must be restarted, or the system rebooted."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=5098
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4816e1b7"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gnutls-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 5.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"gnutls-1.4.1-7.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-debuginfo-1.4.1-7.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-devel-1.4.1-7.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"gnutls-utils-1.4.1-7.el5_8.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gnutls / gnutls-debuginfo / gnutls-devel / gnutls-utils");
}
