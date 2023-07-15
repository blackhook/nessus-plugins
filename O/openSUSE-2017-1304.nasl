#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1304.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104767);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-12837", "CVE-2017-12883", "CVE-2017-6512");

  script_name(english:"openSUSE Security Update : perl (openSUSE-2017-1304)");
  script_summary(english:"Check for the openSUSE-2017-1304 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for perl fixes the following issues :

Security issues fixed :

  - CVE-2017-12837: Heap-based buffer overflow in the
    S_regatom function in regcomp.c in Perl 5 before
    5.24.3-RC1 and 5.26.x before 5.26.1-RC1 allows remote
    attackers to cause a denial of service (out-of-bounds
    write) via a regular expression with a '\N()' escape and
    the case-insensitive modifier. (bnc#1057724)

  - CVE-2017-12883: Buffer overflow in the S_grok_bslash_N
    function in regcomp.c in Perl 5 before 5.24.3-RC1 and
    5.26.x before 5.26.1-RC1 allows remote attackers to
    disclose sensitive information or cause a denial of
    service (application crash) via a crafted regular
    expression with an invalid '\N(U+...)' escape.
    (bnc#1057721)

  - CVE-2017-6512: Race condition in the rmtree and
    remove_tree functions in the File-Path module before
    2.13 for Perl allows attackers to set the mode on
    arbitrary files via vectors involving
    directory-permission loosening logic. (bnc#1047178)

Bug fixes :

  - backport set_capture_string changes from upstream
    (bsc#999735)

  - reformat baselibs.conf as source validator workaround

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057721"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999735"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected perl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-base-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/27");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"perl-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-base-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-base-debuginfo-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-debuginfo-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"perl-debugsource-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"perl-32bit-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"perl-base-32bit-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"perl-base-debuginfo-32bit-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.18.2-6.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-base-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-base-debuginfo-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-debuginfo-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"perl-debugsource-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"perl-32bit-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"perl-base-32bit-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"perl-base-debuginfo-32bit-5.18.2-9.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"perl-debuginfo-32bit-5.18.2-9.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "perl-32bit / perl / perl-base-32bit / perl-base / etc");
}
