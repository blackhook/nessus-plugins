#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2017-8f27031c8f.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103314);
  script_version("3.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2014-9907", "CVE-2016-5010", "CVE-2016-5841", "CVE-2016-6491", "CVE-2016-8707", "CVE-2016-9556", "CVE-2017-10928", "CVE-2017-10995", "CVE-2017-11141", "CVE-2017-11170", "CVE-2017-11188", "CVE-2017-11352", "CVE-2017-11360", "CVE-2017-11446", "CVE-2017-11447", "CVE-2017-11448", "CVE-2017-11449", "CVE-2017-11450", "CVE-2017-11523", "CVE-2017-11639", "CVE-2017-11640", "CVE-2017-11644", "CVE-2017-11724", "CVE-2017-12140", "CVE-2017-12418", "CVE-2017-12427", "CVE-2017-12433", "CVE-2017-12587", "CVE-2017-12640", "CVE-2017-7941", "CVE-2017-9098", "CVE-2017-9141");
  script_xref(name:"FEDORA", value:"2017-8f27031c8f");

  script_name(english:"Fedora 26 : 1:emacs / ImageMagick / WindowMaker / autotrace / converseen / etc (2017-8f27031c8f)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Many security fixes, bug fixes, and other changes from the previous
version 6.9.3.0. See the [6.9 branch
ChangeLog](https://github.com/ImageMagick/ImageMagick/blob/3fd358e2ac3
4977fda38a2cf4d88a1cb4dd2d7c7/ChangeLog).

Dependent packages are mostly straight rebuilds, a couple also include
bugfix version updates.

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2017-8f27031c8f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:1:emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:WindowMaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:autotrace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:converseen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dmtx-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:drawtiming");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:gtatool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:imageinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:inkscape");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:k3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:kxstitch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:perl-Image-SubImageFind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:pfstools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:psiconv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:q");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:ripright");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rss-glx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:rubygem-rmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:synfigstudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:techne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:vdr-scraper2vdr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:vips");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:26");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^26([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 26", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC26", reference:"emacs-25.3-3.fc26", epoch:"1")) flag++;
if (rpm_check(release:"FC26", reference:"ImageMagick-6.9.9.13-1.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"WindowMaker-0.95.8-3.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"autotrace-0.31.1-49.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"converseen-0.9.6.2-3.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"dmtx-utils-0.7.4-4.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"drawtiming-0.7.1-22.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"gtatool-2.2.0-6.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"imageinfo-0.05-27.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"inkscape-0.92.1-4.20170510bzr15686.fc26.1")) flag++;
if (rpm_check(release:"FC26", reference:"k3d-0.8.0.6-8.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"kxstitch-1.2.0-9.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"perl-Image-SubImageFind-0.03-13.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"pfstools-2.0.6-3.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"php-pecl-imagick-3.4.3-2.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"psiconv-0.9.8-22.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"q-7.11-29.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"ripright-0.11-5.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"rss-glx-0.9.1.p-29.fc26.1")) flag++;
if (rpm_check(release:"FC26", reference:"rubygem-rmagick-2.16.0-4.fc26.2")) flag++;
if (rpm_check(release:"FC26", reference:"synfig-1.2.0-9.fc26.1")) flag++;
if (rpm_check(release:"FC26", reference:"synfigstudio-1.2.0-5.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"techne-0.2.3-20.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"vdr-scraper2vdr-1.0.5-4.20170611git254122b.fc26")) flag++;
if (rpm_check(release:"FC26", reference:"vips-8.5.8-2.fc26")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "1:emacs / ImageMagick / WindowMaker / autotrace / converseen / etc");
}
