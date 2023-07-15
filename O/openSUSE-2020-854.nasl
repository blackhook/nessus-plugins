#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-854.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(138700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/28");

  script_cve_id("CVE-2019-17006", "CVE-2020-12399");

  script_name(english:"openSUSE Security Update : mozilla-nspr / mozilla-nss (openSUSE-2020-854)");
  script_summary(english:"Check for the openSUSE-2020-854 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for mozilla-nspr, mozilla-nss fixes the following issues :

mozilla-nss was updated to version 3.53

  - CVE-2020-12399: Fixed a timing attack on DSA signature
    generation (bsc#1171978).

  - CVE-2019-17006: Added length checks for cryptographic
    primitives (bsc#1159819). Release notes:
    https://developer.mozilla.org/en-US/docs/Mozilla/Project
    s/NSS/NSS_3.53_release_notes

mozilla-nspr to version 4.25

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159819"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1171978"
  );
  # https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/NSS_3.53_release_notes
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8e687237"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected mozilla-nspr / mozilla-nss packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfreebl3-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsoftokn3-hmac-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nspr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-certs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-sysinit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mozilla-nss-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");
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

if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libfreebl3-hmac-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libsoftokn3-hmac-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-4.25-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-debuginfo-4.25-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-debugsource-4.25-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nspr-devel-4.25-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-certs-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-certs-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-debugsource-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-devel-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-sysinit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-sysinit-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-tools-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"mozilla-nss-tools-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-32bit-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libfreebl3-hmac-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-32bit-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libsoftokn3-hmac-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-4.25-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nspr-32bit-debuginfo-4.25-lp151.2.9.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-32bit-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-certs-32bit-debuginfo-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-3.53-lp151.2.23.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"mozilla-nss-sysinit-32bit-debuginfo-3.53-lp151.2.23.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mozilla-nspr / mozilla-nspr-debuginfo / mozilla-nspr-debugsource / etc");
}
