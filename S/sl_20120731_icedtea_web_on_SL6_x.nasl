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
  script_id(61406);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2012-3422", "CVE-2012-3423");

  script_name(english:"Scientific Linux Security Update : icedtea-web on SL6.x i386/x86_64 (20120731)");
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
"The IcedTea-Web project provides a Java web browser plug-in and an
implementation of Java Web Start, which is based on the Netx project.
It also contains a configuration tool for managing deployment settings
for the plug-in and Web Start implementations.

An uninitialized pointer use flaw was found in the IcedTea-Web
plug-in. Visiting a malicious web page could possibly cause a web
browser using the IcedTea-Web plug-in to crash, disclose a portion of
its memory, or execute arbitrary code. (CVE-2012-3422)

It was discovered that the IcedTea-Web plug-in incorrectly assumed all
strings received from the browser were NUL terminated. When using the
plug-in with a web browser that does not NUL terminate strings,
visiting a web page containing a Java applet could possibly cause the
browser to crash, disclose a portion of its memory, or execute
arbitrary code. (CVE-2012-3423)

This erratum also upgrades IcedTea-Web to version 1.2.1.

All IcedTea-Web users should upgrade to these updated packages, which
resolve these issues. Web browsers using the IcedTea-Web browser
plug-in must be restarted for this update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=77
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?791f8840"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Update the affected icedtea-web, icedtea-web-debuginfo and / or
icedtea-web-javadoc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:icedtea-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:icedtea-web-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:icedtea-web-javadoc");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
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
if (rpm_check(release:"SL6", reference:"icedtea-web-1.2.1-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-debuginfo-1.2.1-1.el6_3")) flag++;
if (rpm_check(release:"SL6", reference:"icedtea-web-javadoc-1.2.1-1.el6_3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "icedtea-web / icedtea-web-debuginfo / icedtea-web-javadoc");
}
