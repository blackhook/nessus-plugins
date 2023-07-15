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
  script_id(87570);
  script_version("2.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1752", "CVE-2013-1753", "CVE-2014-4616", "CVE-2014-4650", "CVE-2014-7185", "CVE-2014-9365");

  script_name(english:"Scientific Linux Security Update : python on SL7.x x86_64 (20151119)");
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
"It was discovered that the Python xmlrpclib module did not restrict
the size of gzip-compressed HTTP responses. A malicious XMLRPC server
could cause an XMLRPC client using xmlrpclib to consume an excessive
amount of memory. (CVE-2013-1753)

It was discovered that multiple Python standard library modules
implementing network protocols (such as httplib or smtplib) failed to
restrict the sizes of server responses. A malicious server could cause
a client using one of the affected modules to consume an excessive
amount of memory. (CVE-2013-1752)

It was discovered that the CGIHTTPServer module incorrectly handled
URL encoded paths. A remote attacker could use this flaw to execute
scripts outside of the cgi-bin directory, or disclose the source code
of the scripts in the cgi-bin directory. (CVE-2014-4650)

An integer overflow flaw was found in the way the buffer() function
handled its offset and size arguments. An attacker able to control
these arguments could use this flaw to disclose portions of the
application memory or cause it to crash. (CVE-2014-7185)

A flaw was found in the way the json module handled negative index
arguments passed to certain functions (such as raw_decode()). An
attacker able to control the index value passed to one of the affected
functions could possibly use this flaw to disclose portions of the
application memory. (CVE-2014-4616)

The Python standard library HTTP client modules (such as httplib or
urllib) did not perform verification of TLS/SSL certificates when
connecting to HTTPS servers. A man-in-the-middle attacker could use
this flaw to hijack connections and eavesdrop or modify transferred
data. (CVE-2014-9365)

This update also fixes the following bugs :

  - Subprocesses used with the Eventlet library or regular
    threads previously tried to close epoll file descriptors
    twice, which led to an 'Invalid argument' error.
    Subprocesses have been fixed to close the file
    descriptors only once.

  - When importing the readline module from a Python script,
    Python no longer produces erroneous random characters on
    stdout.

  - The cProfile utility has been fixed to print all values
    that the '-s' option supports when this option is used
    without a correct value.

  - The load_cert_chain() function now accepts 'None' as a
    keyfile argument.

In addition, this update adds the following enhancements :

  - Security enhancements as described in PEP 466 have been
    backported to the Python standard library, for example,
    new features of the ssl module: Server Name Indication
    (SNI) support, support for new TLSv1.x protocols, new
    hash algorithms in the hashlib module, and many more.

  - Support for the ssl.PROTOCOL_TLSv1_2 protocol has been
    added to the ssl library.

  - The ssl.SSLSocket.version() method is now available to
    access information about the version of the SSL protocol
    used in a connection."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1512&L=scientific-linux-errata&F=&S=&P=10966
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d3f33a7f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:python-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:tkinter");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/08");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-debug-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-debuginfo-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-devel-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libs-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-test-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-tools-2.7.5-34.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tkinter-2.7.5-34.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
}
