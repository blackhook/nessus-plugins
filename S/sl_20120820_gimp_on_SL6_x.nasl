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
  script_id(61606);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2011-2896", "CVE-2012-3403", "CVE-2012-3481");

  script_name(english:"Scientific Linux Security Update : gimp on SL6.x i386/x86_64 (20120820)");
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
"The GIMP (GNU Image Manipulation Program) is an image composition and
editing program.

An integer overflow flaw, leading to a heap-based buffer overflow, was
found in the GIMP's GIF image format plug-in. An attacker could create
a specially crafted GIF image file that, when opened, could cause the
GIF plug-in to crash or, potentially, execute arbitrary code with the
privileges of the user running the GIMP. (CVE-2012-3481)

A heap-based buffer overflow flaw was found in the Lempel-Ziv-Welch
(LZW) decompression algorithm implementation used by the GIMP's GIF
image format plug-in. An attacker could create a specially crafted GIF
image file that, when opened, could cause the GIF plug-in to crash or,
potentially, execute arbitrary code with the privileges of the user
running the GIMP. (CVE-2011-2896)

A heap-based buffer overflow flaw was found in the GIMP's KiSS CEL
file format plug-in. An attacker could create a specially crafted KiSS
palette file that, when opened, could cause the CEL plug-in to crash
or, potentially, execute arbitrary code with the privileges of the
user running the GIMP. (CVE-2012-3403)

Users of the GIMP are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. The GIMP
must be restarted for the update to take effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1208&L=scientific-linux-errata&T=0&P=1717
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5b34bf3"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gimp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gimp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gimp-devel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gimp-help-browser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:gimp-libs");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/21");
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
if (rpm_check(release:"SL6", reference:"gimp-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-devel-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-devel-tools-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-help-browser-2.6.9-4.el6_3.3")) flag++;
if (rpm_check(release:"SL6", reference:"gimp-libs-2.6.9-4.el6_3.3")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gimp / gimp-devel / gimp-devel-tools / gimp-help-browser / etc");
}
