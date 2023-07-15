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
  script_id(61282);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-0451", "CVE-2012-0455", "CVE-2012-0456", "CVE-2012-0458", "CVE-2012-0459", "CVE-2012-0460", "CVE-2012-0461");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x, SL6.x i386/x86_64 (20120314)");
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
"Mozilla Firefox is an open source web browser.

Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2012-0461, CVE-2012-0462, CVE-2012-0464)

Two flaws were found in the way Firefox parsed certain Scalable Vector
Graphics (SVG) image files. A web page containing a malicious SVG
image file could cause an information leak, or cause Firefox to crash
or, potentially, execute arbitrary code with the privileges of the
user running Firefox. (CVE-2012-0456, CVE-2012-0457)

A flaw could allow a malicious site to bypass intended restrictions,
possibly leading to a cross-site scripting (XSS) attack if a user were
tricked into dropping a 'javascript:' link onto a frame.
(CVE-2012-0455)

It was found that the home page could be set to a 'javascript:' link.
If a user were tricked into setting such a home page by dragging a
link to the home button, it could cause Firefox to repeatedly crash,
eventually leading to arbitrary code execution with the privileges of
the user running Firefox. (CVE-2012-0458)

A flaw was found in the way Firefox parsed certain web content
containing 'cssText'. A web page containing malicious content could
cause Firefox to crash or, potentially, execute arbitrary code with
the privileges of the user running Firefox. (CVE-2012-0459)

It was found that by using the DOM fullscreen API, untrusted content
could bypass the mozRequestFullscreen security protections. A web page
containing malicious web content could exploit this API flaw to cause
user interface spoofing. (CVE-2012-0460)

A flaw was found in the way Firefox handled pages with multiple
Content Security Policy (CSP) headers. This could lead to a cross-site
scripting attack if used in conjunction with a website that has a
header injection flaw. (CVE-2012-0451)

For technical details regarding these flaws, refer to the Mozilla
security advisories for Firefox 10.0.3 ESR. You can find a link to the
Mozilla advisories in the References section of this erratum.

This update also fixes the following bugs :

  - When using the Traditional Chinese locale (zh-TW), a
    segmentation fault sometimes occurred when closing
    Firefox.

  - Inputting any text in the Web Console (Tools -> Web
    Developer -> Web Console) caused Firefox to crash.

All Firefox users should upgrade to these updated packages, which
contain Firefox version 10.0.3 ESR, which corrects these issues. After
installing the update, Firefox must be restarted for the changes to
take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1203&L=scientific-linux-errata&T=0&P=1994
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c6e9781c"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/14");
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
if (rpm_check(release:"SL5", reference:"firefox-10.0.3-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-10.0.3-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-10.0.3-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-10.0.3-1.el5_8")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-10.0.3-1.el5_8")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-10.0.3-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-10.0.3-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-10.0.3-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-10.0.3-1.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-10.0.3-1.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo / xulrunner / xulrunner-debuginfo / etc");
}
