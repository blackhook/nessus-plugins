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
  script_id(64777);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-0775", "CVE-2013-0776", "CVE-2013-0780", "CVE-2013-0782", "CVE-2013-0783");

  script_name(english:"Scientific Linux Security Update : firefox on SL5.x, SL6.x i386/x86_64 (20130219)");
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
running Firefox. (CVE-2013-0775, CVE-2013-0780, CVE-2013-0782,
CVE-2013-0783)

It was found that, after canceling a proxy server's authentication
prompt, the address bar continued to show the requested site's
address. An attacker could use this flaw to conduct phishing attacks
by tricking a user into believing they are viewing a trusted site.
(CVE-2013-0776)

Note that due to a Kerberos credentials change, the following
configuration steps may be required when using Firefox 17.0.3 ESR with
the Enterprise Identity Management (IPA) web interface :

Important: Firefox 17 is not completely backwards-compatible with all
Mozilla add-ons and Firefox plug-ins that worked with Firefox 10.0.
Firefox 17 checks compatibility on first-launch, and, depending on the
individual configuration and the installed add-ons and plug-ins, may
disable said Add-ons and plug-ins, or attempt to check for updates and
upgrade them. Add-ons and plug-ins may have to be manually updated.

After installing the update, Firefox must be restarted for the changes
to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1302&L=scientific-linux-errata&T=0&P=3075
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5592e93b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:devhelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:devhelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:devhelp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:firefox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-mozjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libproxy-webkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xulrunner-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xulrunner-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yelp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:yelp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/21");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL5", reference:"devhelp-0.12-23.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"devhelp-debuginfo-0.12-23.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"devhelp-devel-0.12-23.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-17.0.3-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"firefox-debuginfo-17.0.3-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-17.0.3-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-debuginfo-17.0.3-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"xulrunner-devel-17.0.3-1.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"yelp-2.16.0-30.el5_9")) flag++;
if (rpm_check(release:"SL5", reference:"yelp-debuginfo-2.16.0-30.el5_9")) flag++;

if (rpm_check(release:"SL6", reference:"firefox-17.0.3-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"firefox-debuginfo-17.0.3-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-bin-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-debuginfo-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-devel-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-gnome-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-kde-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-mozjs-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-python-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"libproxy-webkit-0.3.0-4.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-17.0.3-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-debuginfo-17.0.3-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"xulrunner-devel-17.0.3-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"yelp-2.28.1-17.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"yelp-debuginfo-2.28.1-17.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "devhelp / devhelp-debuginfo / devhelp-devel / firefox / etc");
}
