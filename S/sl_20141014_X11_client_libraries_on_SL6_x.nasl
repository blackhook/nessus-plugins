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
  script_id(78841);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2013-1981", "CVE-2013-1982", "CVE-2013-1983", "CVE-2013-1984", "CVE-2013-1985", "CVE-2013-1986", "CVE-2013-1987", "CVE-2013-1988", "CVE-2013-1989", "CVE-2013-1990", "CVE-2013-1991", "CVE-2013-1995", "CVE-2013-1997", "CVE-2013-1998", "CVE-2013-1999", "CVE-2013-2000", "CVE-2013-2001", "CVE-2013-2002", "CVE-2013-2003", "CVE-2013-2004", "CVE-2013-2005", "CVE-2013-2062", "CVE-2013-2064", "CVE-2013-2066");

  script_name(english:"Scientific Linux Security Update : X11 client libraries on SL6.x i386/x86_64 (20141014)");
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
"Multiple integer overflow flaws, leading to heap-based buffer
overflows, were found in the way various X11 client libraries handled
certain protocol data. An attacker able to submit invalid protocol
data to an X11 server via a malicious X11 client could use either of
these flaws to potentially escalate their privileges on the system.
(CVE-2013-1981, CVE-2013-1982, CVE-2013-1983, CVE-2013-1984,
CVE-2013-1985, CVE-2013-1986, CVE-2013-1987, CVE-2013-1988,
CVE-2013-1989, CVE-2013-1990, CVE-2013-1991, CVE-2013-2003,
CVE-2013-2062, CVE-2013-2064)

Multiple array index errors, leading to heap-based buffer
out-of-bounds write flaws, were found in the way various X11 client
libraries handled data returned from an X11 server. A malicious X11
server could possibly use this flaw to execute arbitrary code with the
privileges of the user running an X11 client. (CVE-2013-1997,
CVE-2013-1998, CVE-2013-1999, CVE-2013-2000, CVE-2013-2001,
CVE-2013-2002, CVE-2013-2066)

A buffer overflow flaw was found in the way the XListInputDevices()
function of X.Org X11's libXi runtime library handled signed numbers.
A malicious X11 server could possibly use this flaw to execute
arbitrary code with the privileges of the user running an X11 client.
(CVE-2013-1995)

A flaw was found in the way the X.Org X11 libXt runtime library used
uninitialized pointers. A malicious X11 server could possibly use this
flaw to execute arbitrary code with the privileges of the user running
an X11 client. (CVE-2013-2005)

Two stack-based buffer overflow flaws were found in the way libX11,
the Core X11 protocol client library, processed certain user-specified
files. A malicious X11 server could possibly use this flaw to crash an
X11 client via a specially crafted file. (CVE-2013-2004)

The xkeyboard-config package has been upgraded to upstream version
2.11, which provides a number of bug fixes and enhancements over the
previous version.

This update also fixes the following bugs :

  - Previously, updating the mesa-libGL package did not
    update the libX11 package, although it was listed as a
    dependency of mesa-libGL. This bug has been fixed and
    updating mesa-libGL now updates all dependent packages
    as expected.

  - Previously, closing a customer application could
    occasionally cause the X Server to terminate
    unexpectedly. After this update, the X Server no longer
    hangs when a user closes a customer application."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1411&L=scientific-linux-errata&T=0&P=1476
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cb540d84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libX11-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXcursor-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXext-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXext-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfixes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfixes-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXfixes-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXinerama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXinerama-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXinerama-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrandr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrandr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrandr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrender");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrender-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXrender-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXres");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXres-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXres-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXtst");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXtst-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXtst-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXvMC");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXvMC-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXvMC-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86dga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86dga-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86dga-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86vm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86vm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libXxf86vm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdmx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdmx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libdmx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libxcb-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xcb-proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xkeyboard-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xkeyboard-config-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-proto-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:xorg-x11-xtrans-devel");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/04");
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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Scientific Linux 6.x", "Scientific Linux " + os_ver);
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL6", reference:"libX11-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libX11-common-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libX11-debuginfo-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libX11-devel-1.6.0-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcursor-1.1.14-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcursor-debuginfo-1.1.14-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXcursor-devel-1.1.14-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXext-1.3.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXext-debuginfo-1.3.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXext-devel-1.3.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfixes-5.0.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfixes-debuginfo-5.0.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXfixes-devel-5.0.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXi-1.7.2-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXi-debuginfo-1.7.2-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXi-devel-1.7.2-2.2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXinerama-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXinerama-debuginfo-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXinerama-devel-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXp-1.0.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXp-debuginfo-1.0.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXp-devel-1.0.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrandr-1.4.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrandr-debuginfo-1.4.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrandr-devel-1.4.1-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrender-0.9.8-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrender-debuginfo-0.9.8-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXrender-devel-0.9.8-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXres-1.0.7-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXres-debuginfo-1.0.7-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXres-devel-1.0.7-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXt-1.1.4-6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXt-debuginfo-1.1.4-6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXt-devel-1.1.4-6.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXtst-1.2.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXtst-debuginfo-1.2.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXtst-devel-1.2.2-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXv-1.0.9-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXv-debuginfo-1.0.9-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXv-devel-1.0.9-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXvMC-1.0.8-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXvMC-debuginfo-1.0.8-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXvMC-devel-1.0.8-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86dga-1.1.4-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86dga-debuginfo-1.1.4-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86dga-devel-1.1.4-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86vm-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86vm-debuginfo-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libXxf86vm-devel-1.1.3-2.1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libdmx-1.1.3-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libdmx-debuginfo-1.1.3-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libdmx-devel-1.1.3-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-1.9.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-debuginfo-1.9.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-devel-1.9.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-doc-1.9.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"libxcb-python-1.9.1-2.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xcb-proto-1.8-3.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xkeyboard-config-2.11-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xkeyboard-config-devel-2.11-1.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-proto-devel-7.7-9.el6")) flag++;
if (rpm_check(release:"SL6", reference:"xorg-x11-xtrans-devel-1.3.4-1.el6")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libX11 / libX11-common / libX11-debuginfo / libX11-devel / etc");
}
