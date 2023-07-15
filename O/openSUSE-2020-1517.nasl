#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1517.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141151);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2016-9398", "CVE-2016-9399", "CVE-2017-14132", "CVE-2017-5499", "CVE-2017-5503", "CVE-2017-5504", "CVE-2017-5505", "CVE-2017-9782", "CVE-2018-18873", "CVE-2018-19139", "CVE-2018-19543", "CVE-2018-20570", "CVE-2018-20622", "CVE-2018-9252");

  script_name(english:"openSUSE Security Update : jasper (openSUSE-2020-1517)");
  script_summary(english:"Check for the openSUSE-2020-1517 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for jasper fixes the following issues :

  - CVE-2016-9398: Improved patch for already fixed issue
    (bsc#1010979).

  - CVE-2016-9399: Fix assert in calcstepsizes
    (bsc#1010980).

  - CVE-2017-5499: Validate component depth bit
    (bsc#1020451).

  - CVE-2017-5503: Check bounds in jas_seq2d_bindsub()
    (bsc#1020456).

  - CVE-2017-5504: Check bounds in jas_seq2d_bindsub()
    (bsc#1020458).

  - CVE-2017-5505: Check bounds in jas_seq2d_bindsub()
    (bsc#1020460).

  - CVE-2017-14132: Fix heap base overflow in by checking
    components (bsc#1057152).

  - CVE-2018-9252: Fix reachable assertion in
    jpc_abstorelstepsize (bsc#1088278).

  - CVE-2018-18873: Fix NULL pointer deref in ras_putdatastd
    (bsc#1114498).

  - CVE-2018-19139: Fix mem leaks by registering
    jpc_unk_destroyparms (bsc#1115637).

  - CVE-2018-19543, bsc#1045450 CVE-2017-9782: Fix numchans
    mixup (bsc#1117328).

  - CVE-2018-20570: Fix heap based buffer over-read in
    jp2_encode (bsc#1120807).

  - CVE-2018-20622: Fix memory leak in jas_malloc.c
    (bsc#1120805).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1010980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020458"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1020460"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1045450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1088278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1117328"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120805"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1120807"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected jasper packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:jasper-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper4-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libjasper4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"jasper-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"jasper-debuginfo-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"jasper-debugsource-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libjasper-devel-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libjasper4-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libjasper4-debuginfo-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libjasper4-32bit-2.0.14-lp151.4.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libjasper4-32bit-debuginfo-2.0.14-lp151.4.9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "jasper / jasper-debuginfo / jasper-debugsource / libjasper-devel / etc");
}
