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
  script_id(93072);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2016-0772", "CVE-2016-1000110", "CVE-2016-5699");

  script_name(english:"Scientific Linux Security Update : python on SL6.x, SL7.x i386/x86_64 (20160818) (httpoxy)");
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

  - It was discovered that the Python CGIHandler class did
    not properly protect against the HTTP_PROXY variable
    name clash in a CGI context. A remote attacker could
    possibly use this flaw to redirect HTTP requests
    performed by a Python CGI script to an
    attacker-controlled proxy via a malicious HTTP request.
    (CVE-2016-1000110)

  - It was found that Python's smtplib library did not
    return an exception when StartTLS failed to be
    established in the SMTP.starttls() function. A man in
    the middle attacker could strip out the STARTTLS command
    without generating an exception on the Python SMTP
    client application, preventing the establishment of the
    TLS layer. (CVE-2016-0772)

  - It was found that the Python's httplib library (used by
    urllib, urllib2 and others) did not properly check
    HTTPConnection.putheader() function arguments. An
    attacker could use this flaw to inject additional
    headers in a Python application that allowed user
    provided header names or values. (CVE-2016-5699)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1608&L=scientific-linux-errata&F=&S=&P=6431
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c9fd6492"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/08/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 7.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"python-2.6.6-66.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"python-debuginfo-2.6.6-66.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"python-devel-2.6.6-66.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"python-libs-2.6.6-66.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"python-test-2.6.6-66.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"python-tools-2.6.6-66.el6_8")) flag++;
if (rpm_check(release:"SL6", reference:"tkinter-2.6.6-66.el6_8")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-debug-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-debuginfo-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-devel-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-libs-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-test-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"python-tools-2.7.5-38.el7_2")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"tkinter-2.7.5-38.el7_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python / python-debug / python-debuginfo / python-devel / etc");
}
