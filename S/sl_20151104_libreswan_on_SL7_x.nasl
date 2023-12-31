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
  script_id(86749);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-3240");

  script_name(english:"Scientific Linux Security Update : libreswan on SL7.x x86_64 (20151104)");
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
"A flaw was discovered in the way Libreswan's IKE daemon processed IKE
KE payloads. A remote attacker could send specially crafted IKE
payload with a KE payload of g^x=0 that, when processed, would lead to
a denial of service (daemon crash). (CVE-2015-3240)

Note: Please note that when upgrading from an earlier version of
Libreswan, the existing CA certificates in the /etc/ipsec.d/cacerts/
directory and the existing certificate revocation list (CRL) files
from the /etc/ipsec.d/crls/ directory are automatically imported into
the NSS database. Once completed, these directories are no longer used
by Libreswan. To install new CA certificates or new CRLS, the certutil
and crlutil commands must be used to import these directly into the
Network Security Services (NSS) database.

This update also adds the following enhancements :

  - This update adds support for RFC 7383 IKEv2
    Fragmentation, RFC 7619 Auth Null and ID Null,
    INVALID_KE renegotiation, CRL and OCSP support via NSS,
    AES_CTR and AES_GCM support for IKEv2, CAVS testing for
    FIPS compliance.

In addition, this update enforces FIPS algorithms restrictions in FIPS
mode, and runs Composite Application Validation System (CAVS) testing
for FIPS compliance during package build. A new Cryptographic
Algorithm Validation Program (CAVP) binary can be used to re-run the
CAVS tests at any time. Regardless of FIPS mode, the pluto daemon runs
RFC test vectors for various algorithms.

Furthermore, compiling on all architectures now enables the '-Werror'
GCC option, which enhances the security by making all warnings into
errors.

  - This update also fixes several memory leaks and
    introduces a sub-second packet retransmit option.

  - This update improves migration support from Openswan to
    Libreswan. Specifically, all Openswan options that can
    take a time value without a suffix are now supported,
    and several new keywords for use in the /etc/ipsec.conf
    file have been introduced. See the relevant man pages
    for details.

  - With this update, loopback support via the 'loopback='
    option has been deprecated."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1511&L=scientific-linux-errata&F=&S=&P=1678
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5cc1186c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libreswan and / or libreswan-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libreswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreswan-3.15-5.el7_1")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libreswan-debuginfo-3.15-5.el7_1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libreswan / libreswan-debuginfo");
}
