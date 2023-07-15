#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-358.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(146916);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/10");

  script_cve_id(
    "CVE-2019-25013",
    "CVE-2020-27618",
    "CVE-2020-29562",
    "CVE-2020-29573",
    "CVE-2021-3326"
  );

  script_name(english:"openSUSE Security Update : glibc (openSUSE-2021-358)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for glibc fixes the following issues :

  - Fix buffer overrun in EUC-KR conversion module
    (CVE-2019-25013, bsc#1182117, BZ #24973)

  - x86: Harden printf against non-normal long double values
    (CVE-2020-29573, bsc#1179721, BZ #26649)

  - gconv: Fix assertion failure in ISO-2022-JP-3 module
    (CVE-2021-3326, bsc#1181505, BZ #27256)

  - iconv: Accept redundant shift sequences in IBM1364
    (CVE-2020-27618, bsc#1178386, BZ #26224)

  - iconv: Fix incorrect UCS4 inner loop bounds
    (CVE-2020-29562, bsc#1179694, BZ #26923)

  - Fix parsing of /sys/devices/system/cpu/online
    (bsc#1180038, BZ #25859)

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179694");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1179721");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1180038");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181505");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1182117");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-25013");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-3326");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-devel-static-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-i18ndata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-base-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-base-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-locale-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-profile-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:glibc-utils-src-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nscd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"glibc-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-debugsource-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-devel-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-devel-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-devel-static-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-extra-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-extra-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-html-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-i18ndata-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-info-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-locale-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-locale-base-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-locale-base-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-profile-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-utils-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-utils-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"glibc-utils-src-debugsource-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nscd-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nscd-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-32bit-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-32bit-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-devel-32bit-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-devel-32bit-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-devel-static-32bit-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-locale-base-32bit-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-locale-base-32bit-debuginfo-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-profile-32bit-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-utils-32bit-2.26-lp152.26.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"glibc-utils-32bit-debuginfo-2.26-lp152.26.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc / glibc-debuginfo / glibc-debugsource / glibc-devel / etc");
}
