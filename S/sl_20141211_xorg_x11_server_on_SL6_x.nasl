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
  script_id(80018);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2014-8091", "CVE-2014-8092", "CVE-2014-8093", "CVE-2014-8094", "CVE-2014-8095", "CVE-2014-8096", "CVE-2014-8097", "CVE-2014-8098", "CVE-2014-8099", "CVE-2014-8100", "CVE-2014-8101", "CVE-2014-8102", "CVE-2014-8103");

  script_name(english:"Scientific Linux Security Update : xorg-x11-server on SL6.x, SL7.x i386/x86_64 (20141211)");
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
"Multiple integer overflow flaws and out-of-bounds write flaws were
found in the way the X.Org server calculated memory requirements for
certain X11 core protocol and GLX extension requests. A malicious,
authenticated client could use either of these flaws to crash the
X.Org server or, potentially, execute arbitrary code with root
privileges. (CVE-2014-8092, CVE-2014-8093, CVE-2014-8098)

It was found that the X.Org server did not properly handle SUN-DES-1
(Secure RPC) authentication credentials. A malicious, unauthenticated
client could use this flaw to crash the X.Org server by submitting a
specially crafted authentication request. (CVE-2014-8091)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server, or leak memory contents to the client.
(CVE-2014-8097)

An integer overflow flaw was found in the way the X.Org server
calculated memory requirements for certain DRI2 extension requests. A
malicious, authenticated client could use this flaw to crash the X.Org
server. (CVE-2014-8094)

Multiple out-of-bounds access flaws were found in the way the X.Org
server calculated memory requirements for certain requests. A
malicious, authenticated client could use either of these flaws to
crash the X.Org server. (CVE-2014-8095, CVE-2014-8096, CVE-2014-8099,
CVE-2014-8100, CVE-2014-8101, CVE-2014-8102, CVE-2014-8103)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1412&L=scientific-linux-errata&T=0&P=1959
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a2f5c34f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xephyr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xnest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xorg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-Xvfb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-server-source");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");
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
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xdmx-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xephyr-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xnest-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xorg-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-Xvfb-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-common-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-debuginfo-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-devel-1.15.0-25.sl6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-server-source-1.15.0-25.sl6")) flag++;

if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xdmx-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xephyr-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xnest-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xorg-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-Xvfb-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-common-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-debuginfo-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"xorg-x11-server-devel-1.15.0-7.el7_0.3")) flag++;
if (rpm_check(release:"SL7", reference:"xorg-x11-server-source-1.15.0-7.el7_0.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xorg-x11-server-Xdmx / xorg-x11-server-Xephyr / etc");
}
