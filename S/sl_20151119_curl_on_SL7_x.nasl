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
  script_id(87554);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-3613", "CVE-2014-3707", "CVE-2014-8150", "CVE-2015-3143", "CVE-2015-3148");

  script_name(english:"Scientific Linux Security Update : curl on SL7.x x86_64 (20151119)");
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
"It was found that the libcurl library did not correctly handle partial
literal IP addresses when parsing received HTTP cookies. An attacker
able to trick a user into connecting to a malicious server could use
this flaw to set the user's cookie to a crafted domain, making other
cookie-related issues easier to exploit. (CVE-2014-3613)

A flaw was found in the way the libcurl library performed the
duplication of connection handles. If an application set the
CURLOPT_COPYPOSTFIELDS option for a handle, using the handle's
duplicate could cause the application to crash or disclose a portion
of its memory. (CVE-2014-3707)

It was discovered that the libcurl library failed to properly handle
URLs with embedded end-of-line characters. An attacker able to make an
application using libcurl access a specially crafted URL via an HTTP
proxy could use this flaw to inject additional headers to the request
or construct additional requests. (CVE-2014-8150)

It was discovered that libcurl implemented aspects of the NTLM and
Negotatiate authentication incorrectly. If an application uses libcurl
and the affected mechanisms in a specifc way, certain requests to a
previously NTLM-authenticated server could appears as sent by the
wrong authenticated user. Additionally, the initial set of credentials
for HTTP Negotiate- authenticated requests could be reused in
subsequent requests, although a different set of credentials was
specified. (CVE-2015-3143, CVE-2015-3148)

Bug fixes :

  - An out-of-protocol fallback to SSL 3.0 was available
    with libcurl. Attackers could abuse the fallback to
    force downgrade of the SSL version. The fallback has
    been removed from libcurl. Users requiring this
    functionality can explicitly enable SSL 3.0 through the
    libcurl API.

  - TLS 1.1 and TLS 1.2 are no longer disabled by default in
    libcurl. You can explicitly disable them through the
    libcurl API.

  - FTP operations such as downloading files took a
    significantly long time to complete. Now, the FTP
    implementation in libcurl correctly sets blocking
    direction and estimated timeout for connections,
    resulting in faster FTP transfers.

Enhancements :

  - With the updated packages, it is possible to explicitly
    enable or disable new Advanced Encryption Standard (AES)
    cipher suites to be used for the TLS protocol.

  - The libcurl library did not implement a non-blocking SSL
    handshake, which negatively affected performance of
    applications based on the libcurl multi API. The
    non-blocking SSL handshake has been implemented in
    libcurl, and the libcurl multi API now immediately
    returns the control back to the application whenever it
    cannot read or write data from or to the underlying
    network socket.

  - The libcurl library used an unnecessarily long blocking
    delay for actions with no active file descriptors, even
    for short operations. Some actions, such as resolving a
    host name using /etc/hosts, took a long time to
    complete. The blocking code in libcurl has been modified
    so that the initial delay is short and gradually
    increases until an event occurs."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=14587
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f59fa770"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libcurl-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/22");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"curl-7.29.0-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"curl-debuginfo-7.29.0-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcurl-7.29.0-25.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libcurl-devel-7.29.0-25.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl / curl-debuginfo / libcurl / libcurl-devel");
}
