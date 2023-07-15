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
  script_id(85196);
  script_version("2.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-5704");

  script_name(english:"Scientific Linux Security Update : httpd on SL6.x i386/x86_64 (20150722)");
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
"A flaw was found in the way httpd handled HTTP Trailer headers when
processing requests using chunked encoding. A malicious client could
use Trailer headers to set additional HTTP headers after header
processing was performed by other modules. This could, for example,
lead to a bypass of header restrictions defined with mod_headers.
(CVE-2013-5704)

This update also fixes the following bugs :

  - The order of mod_proxy workers was not checked when
    httpd configuration was reloaded. When mod_proxy workers
    were removed, added, or their order was changed, their
    parameters and scores could become mixed. The order of
    mod_proxy workers has been made internally consistent
    during configuration reload.

  - The local host certificate created during firstboot
    contained CA extensions, which caused the httpd service
    to return warning messages. This has been addressed by
    local host certificates being generated with the
    '-extensions v3_req' option.

  - The default mod_ssl configuration no longer enables
    support for SSL cipher suites using the single DES,
    IDEA, or SEED encryption algorithms.

  - The apachectl script did not take into account the
    HTTPD_LANG variable set in the /etc/sysconfig/httpd file
    during graceful restarts. Consequently, httpd did not
    use a changed value of HTTPD_LANG when the daemon was
    restarted gracefully. The script has been fixed to
    handle the HTTPD_LANG variable correctly.

  - The mod_deflate module failed to check the original file
    size while extracting files larger than 4 GB, making it
    impossible to extract large files. Now, mod_deflate
    checks the original file size properly according to
    RFC1952, and it is able to decompress files larger than
    4 GB.

  - The httpd service did not check configuration before
    restart. When a configuration contained an error, an
    attempt to restart httpd gracefully failed. Now, httpd
    checks configuration before restart and if the
    configuration is in an inconsistent state, an error
    message is printed, httpd is not stopped and a restart
    is not performed.

  - The SSL_CLIENT_VERIFY environment variable was
    incorrectly handled when the 'SSLVerifyClient
    optional_no_ca' and 'SSLSessionCache' options were used.
    When an SSL session was resumed, the SSL_CLIENT_VERIFY
    value was set to 'SUCCESS' instead of the previously set
    'GENEROUS'. SSL_CLIENT_VERIFY is now correctly set to
    GENEROUS in this scenario.

  - The ab utility did not correctly handle situations when
    an SSL connection was closed after some data had already
    been read. As a consequence, ab did not work correctly
    with SSL servers and printed 'SSL read failed' error
    messages. With this update, ab works as expected with
    HTTPS servers.

  - When a client presented a revoked certificate, log
    entries were created only at the debug level. The log
    level of messages regarding a revoked certificate has
    been increased to INFO, and administrators are now
    properly informed of this situation.

In addition, this update adds the following enhancement :

  - A mod_proxy worker can now be set into drain mode (N)
    using the balancer-manager web interface or using the
    httpd configuration file. A worker in drain mode accepts
    only existing sticky sessions destined for itself and
    ignores all other requests. The worker waits until all
    clients currently connected to this worker complete
    their work before the worker is stopped. As a result,
    drain mode enables to perform maintenance on a worker
    without affecting clients.

After installing the updated packages, the httpd service will be
restarted automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1508&L=scientific-linux-errata&F=&S=&P=7627
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7425587e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/04");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"httpd-2.2.15-45.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-debuginfo-2.2.15-45.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-devel-2.2.15-45.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-manual-2.2.15-45.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-tools-2.2.15-45.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"mod_ssl-2.2.15-45.sl6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd / httpd-debuginfo / httpd-devel / httpd-manual / httpd-tools / etc");
}
