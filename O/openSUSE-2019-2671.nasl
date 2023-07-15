#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-2671.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(131996);
  script_version("1.2");
  script_cvs_date("Date: 2019/12/16");

  script_cve_id("CVE-2019-14491", "CVE-2019-14492", "CVE-2019-15939");

  script_name(english:"openSUSE Security Update : opencv (openSUSE-2019-2671)");
  script_summary(english:"Check for the openSUSE-2019-2671 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for opencv fixes the following issues :

Security issues fixed :

  - CVE-2019-14491: Fixed an out of bounds read in the
    function cv:predictOrdered<cv:HaarEvaluator>, leading to
    DOS (bsc#1144352).

  - CVE-2019-14492: Fixed an out of bounds read/write in the
    function HaarEvaluator:OptFeature:calc, which leads to
    denial of service (bsc#1144348).

  - CVE-2019-15939: Fixed a divide-by-zero error in
    cv:HOGDescriptor:getDescriptorSize (bsc#1149742).

Non-security issue fixed :

  - Fixed an issue in opencv-devel that broke builds with
    'No rule to make target opencv_calib3d-NOTFOUND'
    (bsc#1154091).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144352"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1149742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154091"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected opencv packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv3_3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libopencv3_3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:opencv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-opencv-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"libopencv3_3-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libopencv3_3-debuginfo-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"opencv-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"opencv-debuginfo-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"opencv-debugsource-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"opencv-devel-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-opencv-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python2-opencv-debuginfo-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-opencv-3.3.1-lp151.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"python3-opencv-debuginfo-3.3.1-lp151.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libopencv3_3 / libopencv3_3-debuginfo / opencv / opencv-debuginfo / etc");
}
