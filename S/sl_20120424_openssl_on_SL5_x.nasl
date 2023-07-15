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
  script_id(61305);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-2110");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x, SL6.x i386/x86_64 (20120424)");
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
"OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL
v2/v3) and Transport Layer Security (TLS v1) protocols, as well as a
full-strength, general purpose cryptography library.

Multiple numeric conversion errors, leading to a buffer overflow, were
found in the way OpenSSL parsed ASN.1 (Abstract Syntax Notation One)
data from BIO (OpenSSL's I/O abstraction) inputs. Specially crafted
DER (Distinguished Encoding Rules) encoded data read from a file or
other BIO input could cause an application using the OpenSSL library
to crash or, potentially, execute arbitrary code. (CVE-2012-2110)

All OpenSSL users should upgrade to these updated packages, which
contain a backported patch to resolve this issue. For the update to
take effect, all services linked to the OpenSSL library must be
restarted, or the system rebooted."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1204&L=scientific-linux-errata&T=0&P=2120
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b255da57"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl097a");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl097a-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl098e");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl098e-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/24");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-22.el5_8.3")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-debuginfo-0.9.8e-22.el5_8.3")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-22.el5_8.3")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-22.el5_8.3")) flag++;
if (rpm_check(release:"SL5", reference:"openssl097a-0.9.7a-11.el5_8.2")) flag++;
if (rpm_check(release:"SL5", reference:"openssl097a-debuginfo-0.9.7a-11.el5_8.2")) flag++;

if (rpm_check(release:"SL6", reference:"openssl-1.0.0-20.el6_2.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.0-20.el6_2.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.0-20.el6_2.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.0-20.el6_2.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.0-20.el6_2.4")) flag++;
if (rpm_check(release:"SL6", reference:"openssl098e-0.9.8e-17.el6_2.2")) flag++;
if (rpm_check(release:"SL6", reference:"openssl098e-debuginfo-0.9.8e-17.el6_2.2")) flag++;


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
