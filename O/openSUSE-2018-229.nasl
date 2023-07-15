#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-229.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(107184);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12596", "CVE-2017-9110", "CVE-2017-9114");

  script_name(english:"openSUSE Security Update : openexr (openSUSE-2018-229)");
  script_summary(english:"Check for the openSUSE-2018-229 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openexr fixes the following issues :

  - CVE-2017-9110: In OpenEXR, an invalid read of size 2 in
    the hufDecode function in ImfHuf.cpp could cause the
    application to crash. (bsc#1040107)

  - CVE-2017-9114: In OpenEXR, an invalid read of size 1 in
    the refill function in ImfFastHuf.cpp could cause the
    application to crash. (bsc#1040114)

  - CVE-2017-12596: In OpenEXR, a crafted image causes a
    heap-based buffer over-read in the hufDecode function in
    IlmImf/ImfHuf.cpp during exrmaketiled execution; it
    could have resulted in denial of service or possibly
    unspecified other impact. (bsc#1052522)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040107"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1040114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052522"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openexr packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-Imf_2_1-21");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-Imf_2_1-21-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-Imf_2_1-21-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libIlmImf-Imf_2_1-21-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openexr-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"libIlmImf-Imf_2_1-21-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libIlmImf-Imf_2_1-21-debuginfo-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openexr-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openexr-debuginfo-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openexr-debugsource-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openexr-devel-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-32bit-2.1.0-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libIlmImf-Imf_2_1-21-debuginfo-32bit-2.1.0-10.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libIlmImf-Imf_2_1-21 / libIlmImf-Imf_2_1-21-32bit / etc");
}
