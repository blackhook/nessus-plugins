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
  script_id(91538);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2015-5234", "CVE-2015-5235");

  script_name(english:"Scientific Linux Security Update : icedtea-web on SL6.x i386/x86_64 (20160510)");
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
"The following packages have been upgraded to a newer upstream version:
icedtea-web (1.6.2).

Security Fix(es) :

  - It was discovered that IcedTea-Web did not properly
    sanitize applet URLs when storing applet trust settings.
    A malicious web page could use this flaw to inject
    trust-settings configuration, and cause applets to be
    executed without user approval. (CVE-2015-5234)

  - It was discovered that IcedTea-Web did not properly
    determine an applet's origin when asking the user if the
    applet should be run. A malicious page could use this
    flaw to cause IcedTea-Web to execute the applet without
    user approval, or confuse the user into approving applet
    execution based on an incorrectly indicated applet
    origin. (CVE-2015-5235)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1606&L=scientific-linux-errata&F=&S=&P=1796
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c16f4bea"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected icedtea-web, icedtea-web-debuginfo and / or
icedtea-web-javadoc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/09");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"icedtea-web-1.6.2-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-debuginfo-1.6.2-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-javadoc-1.6.2-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-debuginfo / icedtea-web-javadoc");
}
