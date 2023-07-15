#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(128224);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/24");

  script_cve_id("CVE-2018-6790");

  script_name(english:"Scientific Linux Security Update : kde-workspace on SL7.x x86_64 (20190806)");
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
"Security Fix(es) :

  - kde-workspace: Missing sanitization of notifications
    allows to leak client IP address via IMG element
    (CVE-2018-6790)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1908&L=SCIENTIFIC-LINUX-ERRATA&P=24388
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a5d6dacd"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kcm_colors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-settings-ksplash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-settings-minimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-settings-plasma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-settings-pulseaudio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-workspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-workspace-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-workspace-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-workspace-ksplash-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kde-workspace-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdeclassic-cursor-theme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdelibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdelibs-apidocs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdelibs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdelibs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdelibs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kdelibs-ktexteditor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kgreeter-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:khotkeys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:khotkeys-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kinfocenter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmag-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kmenuedit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ksysguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ksysguard-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:ksysguardd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kwin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kwin-gles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kwin-gles-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:kwin-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:libkworkspace");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:oxygen-cursor-themes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:plasma-scriptengine-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:plasma-scriptengine-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:qt-settings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virtuoso-opensource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virtuoso-opensource-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fermilab:scientific_linux:virtuoso-opensource-utils");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kcm_colors-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kde-settings-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-settings-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kde-settings-ksplash-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-settings-ksplash-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kde-settings-minimal-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-settings-minimal-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kde-settings-plasma-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-settings-plasma-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kde-settings-pulseaudio-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-settings-pulseaudio-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-style-oxygen-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-workspace-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-workspace-debuginfo-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-workspace-devel-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kde-workspace-ksplash-themes-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-workspace-ksplash-themes-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kde-workspace-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kdeclassic-cursor-theme-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdeclassic-cursor-theme-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdelibs-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", reference:"kdelibs-apidocs-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdelibs-apidocs-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdelibs-common-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdelibs-debuginfo-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdelibs-devel-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kdelibs-ktexteditor-4.14.8-10.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kgreeter-plugins-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"khotkeys-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"khotkeys-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kinfocenter-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmag-4.10.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmag-debuginfo-4.10.5-4.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kmenuedit-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ksysguard-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ksysguard-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"ksysguardd-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kwin-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kwin-gles-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kwin-gles-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"kwin-libs-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"libkworkspace-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"oxygen-cursor-themes-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"oxygen-cursor-themes-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"plasma-scriptengine-python-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"plasma-scriptengine-ruby-4.11.19-13.el7")) flag++;
if (rpm_check(release:"SL7", reference:"qt-settings-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"qt-settings-19-23.9.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"virtuoso-opensource-6.1.6-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"virtuoso-opensource-debuginfo-6.1.6-7.el7")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"virtuoso-opensource-utils-6.1.6-7.el7")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kcm_colors / kde-settings / kde-settings-ksplash / etc");
}
