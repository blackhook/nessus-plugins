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
  script_id(61310);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2010-4167", "CVE-2012-0247", "CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1798");

  script_name(english:"Scientific Linux Security Update : ImageMagick on SL6.x i386/x86_64 (20120507)");
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
"ImageMagick is an image display and manipulation tool for the X Window
System that can read and write multiple image formats.

A flaw was found in the way ImageMagick processed images with
malformed Exchangeable image file format (Exif) metadata. An attacker
could create a specially crafted image file that, when opened by a
victim, would cause ImageMagick to crash or, potentially, execute
arbitrary code. (CVE-2012-0247)

A denial of service flaw was found in the way ImageMagick processed
images with malformed Exif metadata. An attacker could create a
specially crafted image file that, when opened by a victim, could
cause ImageMagick to enter an infinite loop. (CVE-2012-0248)

It was found that ImageMagick utilities tried to load ImageMagick
configuration files from the current working directory. If a user ran
an ImageMagick utility in an attacker-controlled directory containing
a specially crafted ImageMagick configuration file, it could cause the
utility to execute arbitrary code. (CVE-2010-4167)

An integer overflow flaw was found in the way ImageMagick processed
certain Exif tags with a large components count. An attacker could
create a specially crafted image file that, when opened by a victim,
could cause ImageMagick to access invalid memory and crash.
(CVE-2012-0259)

A denial of service flaw was found in the way ImageMagick decoded
certain JPEG images. A remote attacker could provide a JPEG image with
specially crafted sequences of RST0 up to RST7 restart markers (used
to indicate the input stream to be corrupted), which once processed by
ImageMagick, would cause it to consume excessive amounts of memory and
CPU time. (CVE-2012-0260)

An out-of-bounds buffer read flaw was found in the way ImageMagick
processed certain TIFF image files. A remote attacker could provide a
TIFF image with a specially crafted Exif IFD value (the set of tags
for recording Exif-specific attribute information), which once opened
by ImageMagick, would cause it to crash. (CVE-2012-1798)

Users of ImageMagick are advised to upgrade to these updated packages,
which contain backported patches to correct these issues. All running
instances of ImageMagick must be restarted for this update to take
effect."
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1205&L=scientific-linux-errata&T=0&P=74
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3687a350"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-c++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/07");
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
if (rpm_check(release:"SL6", reference:"ImageMagick-6.5.4.7-6.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-c++-6.5.4.7-6.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-c++-devel-6.5.4.7-6.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-debuginfo-6.5.4.7-6.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-devel-6.5.4.7-6.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-doc-6.5.4.7-6.el6_2")) flag++;
if (rpm_check(release:"SL6", reference:"ImageMagick-perl-6.5.4.7-6.el6_2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ImageMagick / ImageMagick-c++ / ImageMagick-c++-devel / etc");
}
