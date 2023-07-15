#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1360.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(105242);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2010-4226", "CVE-2017-14804", "CVE-2017-9274");

  script_name(english:"openSUSE Security Update : the OBS toolchain (openSUSE-2017-1360)");
  script_summary(english:"Check for the openSUSE-2017-1360 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This OBS toolchain update fixes the following issues :

Package 'build' :

  - CVE-2010-4226: force use of bsdtar for VMs (bnc#665768)

  - CVE-2017-14804: Improve file name check extractbuild
    (bsc#1069904)

  - switch baselibs scheme for debuginfo packages from
    foo-debuginfo-32bit to foo-32bit-debuginfo (fate#323217)

Package 'obs-service-source_validator' :

  - CVE-2017-9274: Don't use rpmbuild to extract sources,
    patches etc. from a spec (bnc#938556).

  - Update to version 0.7

  - use spec_query instead of output_versions using the
    specfile parser from the build package (boo#1059858)

Package 'osc' :

  - update to version 0.162.0

  - add Recommends: ca-certificates to enable TLS
    verification without manually installing them.
    (bnc#1061500)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059858"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069904"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=665768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=938556"
  );
  # https://features.opensuse.org/323217
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected the OBS toolchain packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm-i586");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-initvm-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-mkbaselibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:build-mkdrpms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:obs-service-source_validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:osc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"build-20171128-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"build-initvm-i586-20171128-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"build-initvm-x86_64-20171128-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"build-mkbaselibs-20171128-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"build-mkdrpms-20171128-2.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"obs-service-source_validator-0.7-13.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"osc-0.162.0-7.7.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"build-20171128-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"build-initvm-i586-20171128-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"build-initvm-x86_64-20171128-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"build-mkbaselibs-20171128-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"build-mkdrpms-20171128-5.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"obs-service-source_validator-0.7-16.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"osc-0.162.0-10.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "build / build-initvm-i586 / build-mkbaselibs / build-mkdrpms / etc");
}
