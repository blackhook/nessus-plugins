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
  script_id(79712);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-1587", "CVE-2014-1590", "CVE-2014-1592", "CVE-2014-1593", "CVE-2014-1594");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x, SL6.x, SL7.x i386/x86_64 (20141202)");
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
"Several flaws were found in the processing of malformed web content. A
web page containing malicious content could cause Firefox to crash or,
potentially, execute arbitrary code with the privileges of the user
running Firefox. (CVE-2014-1587, CVE-2014-1590, CVE-2014-1592,
CVE-2014-1593)

A flaw was found in the Alarm API, which could allow applications to
schedule actions to be run in the future. A malicious web application
could use this flaw to bypass the same-origin policy. (CVE-2014-1594)

This update disables SSL 3.0 support by default in Firefox. Details on
how to re-enable SSL 3.0 support are available at :

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=706
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?32b7311b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/04");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"firefox-31.3.0-4.el5_11")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-31.3.0-4.el5_11")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-31.3.0-3.el6_6")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-31.3.0-3.el6_6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-31.3.0-3.el7_0")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-debuginfo-31.3.0-3.el7_0")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "firefox / firefox-debuginfo");
}
