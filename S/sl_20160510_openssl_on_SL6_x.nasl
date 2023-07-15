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
  script_id(91541);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-0799", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2107", "CVE-2016-2108", "CVE-2016-2109", "CVE-2016-2842");

  script_name(english:"Scientific Linux Security Update : openssl on SL6.x i386/x86_64 (20160510)");
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
"Security Fix(es) :

  - A flaw was found in the way OpenSSL encoded certain
    ASN.1 data structures. An attacker could use this flaw
    to create a specially crafted certificate which, when
    verified or re-encoded by OpenSSL, could cause it to
    crash, or execute arbitrary code using the permissions
    of the user running an application compiled against the
    OpenSSL library. (CVE-2016-2108)

  - Two integer overflow flaws, leading to buffer overflows,
    were found in the way the EVP_EncodeUpdate() and
    EVP_EncryptUpdate() functions of OpenSSL parsed very
    large amounts of input data. A remote attacker could use
    these flaws to crash an application using OpenSSL or,
    possibly, execute arbitrary code with the permissions of
    the user running that application. (CVE-2016-2105,
    CVE-2016-2106)

  - It was discovered that OpenSSL leaked timing information
    when decrypting TLS/SSL and DTLS protocol encrypted
    records when the connection used the AES CBC cipher
    suite and the server supported AES-NI. A remote attacker
    could possibly use this flaw to retrieve plain text from
    encrypted packets by using a TLS/SSL or DTLS server as a
    padding oracle. (CVE-2016-2107)

  - Several flaws were found in the way BIO_*printf
    functions were implemented in OpenSSL. Applications
    which passed large amounts of untrusted data through
    these functions could crash or potentially execute code
    with the permissions of the user running such an
    application. (CVE-2016-0799, CVE-2016-2842)

  - A denial of service flaw was found in the way OpenSSL
    parsed certain ASN.1-encoded data from BIO (OpenSSL's
    I/O abstraction) inputs. An application using OpenSSL
    that accepts untrusted ASN.1 BIO input could be forced
    to allocate an excessive amount of data. (CVE-2016-2109)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=2153
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?52edfd08"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL6", reference:"openssl-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.1e-48.el6_8.1")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.1e-48.el6_8.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl / openssl-debuginfo / openssl-devel / openssl-perl / etc");
}
