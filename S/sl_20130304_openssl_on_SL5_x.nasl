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
  script_id(65022);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2012-4929", "CVE-2013-0166", "CVE-2013-0169");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Scientific Linux Security Update : openssl on SL5.x, SL6.x i386/x86_64 (20130304)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Scientific Linux host is missing one or more security
updates.");
  script_set_attribute(attribute:"description", value:
"It was discovered that OpenSSL leaked timing information when
decrypting TLS/SSL and DTLS protocol encrypted records when CBC-mode
cipher suites were used. A remote attacker could possibly use this
flaw to retrieve plain text from the encrypted packets by using a
TLS/SSL or DTLS server as a padding oracle. (CVE-2013-0169)

A NULL pointer dereference flaw was found in the OCSP response
verification in OpenSSL. A malicious OCSP server could use this flaw
to crash applications performing OCSP verification by sending a
specially- crafted response. (CVE-2013-0166)

It was discovered that the TLS/SSL protocol could leak information
about plain text when optional compression was used. An attacker able
to control part of the plain text sent over an encrypted TLS/SSL
connection could possibly use this flaw to recover other portions of
the plain text. (CVE-2012-4929)

Note: This update disables zlib compression, which was previously
enabled in OpenSSL by default. Applications using OpenSSL now need to
explicitly enable zlib compression to use it.

It was found that OpenSSL read certain environment variables even when
used by a privileged (setuid or setgid) application. A local attacker
could use this flaw to escalate their privileges. No application
shipped with Scientific Linux 5 and 6 was affected by this problem.

For the update to take effect, all services linked to the OpenSSL
library must be restarted, or the system rebooted.");
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=1414
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?de223d65");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:openssl-static");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Scientific Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (rpm_check(release:"SL5", reference:"openssl-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-debuginfo-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-devel-0.9.8e-26.el5_9.1")) flag++;
if (rpm_check(release:"SL5", reference:"openssl-perl-0.9.8e-26.el5_9.1")) flag++;

if (rpm_check(release:"SL6", reference:"openssl-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-debuginfo-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-devel-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-perl-1.0.0-27.el6_4.2")) flag++;
if (rpm_check(release:"SL6", reference:"openssl-static-1.0.0-27.el6_4.2")) flag++;


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
