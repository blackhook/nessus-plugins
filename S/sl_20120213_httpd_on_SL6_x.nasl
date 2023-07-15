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
  script_id(61245);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-3607", "CVE-2011-3639", "CVE-2011-4317", "CVE-2012-0031", "CVE-2012-0053");

  script_name(english:"Scientific Linux Security Update : httpd on SL6.x i386/x86_64 (20120213)");
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
"The Apache HTTP Server is a popular web server.

It was discovered that the fix for CVE-2011-3368 (released in a
previous update) did not completely address the problem. An attacker
could bypass the fix and make a reverse proxy connect to an arbitrary
server not directly accessible to the attacker by sending an HTTP
version 0.9 request, or by using a specially crafted URI.
(CVE-2011-3639, CVE-2011-4317)

The httpd server included the full HTTP header line in the default
error page generated when receiving an excessively long or malformed
header. Malicious JavaScript running in the server's domain context
could use this flaw to gain access to httpOnly cookies.
(CVE-2012-0053)

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the way httpd performed substitutions in regular expressions.
An attacker able to set certain httpd settings, such as a user
permitted to override the httpd configuration for a specific directory
using a '.htaccess' file, could use this flaw to crash the httpd child
process or, possibly, execute arbitrary code with the privileges of
the 'apache' user. (CVE-2011-3607)

A flaw was found in the way httpd handled child process status
information. A malicious program running with httpd child process
privileges (such as a PHP or CGI script) could use this flaw to cause
the parent httpd process to crash during httpd service shutdown.
(CVE-2012-0031)

All httpd users should upgrade to these updated packages, which
contain backported patches to correct these issues. After installing
the updated packages, the httpd daemon will be restarted
automatically."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1202&L=scientific-linux-errata&T=0&P=2220
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ddbd264"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-14-410");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:httpd-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:mod_ssl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/13");
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
if (rpm_check(release:"SL6", reference:"httpd-2.2.15-15.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-debuginfo-2.2.15-15.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-devel-2.2.15-15.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-manual-2.2.15-15.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"httpd-tools-2.2.15-15.el6_2.1")) flag++;
if (rpm_check(release:"SL6", reference:"mod_ssl-2.2.15-15.el6_2.1")) flag++;


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
