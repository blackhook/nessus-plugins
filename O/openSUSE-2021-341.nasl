#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-341.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(146918);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/03");

  script_cve_id("CVE-2019-18802");

  script_name(english:"openSUSE Security Update : nghttp2 (openSUSE-2021-341)");
  script_summary(english:"Check for the openSUSE-2021-341 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nghttp2 fixes the following issues :

nghttp2 was update to version 1.40.0 (bsc#1166481)

  - lib: Add nghttp2_check_authority as public API

  - lib: Fix the bug that stream is closed with wrong error
    code

  - lib: Faster huffman encoding and decoding

  - build: Avoid filename collision of static and dynamic
    lib

  - build: Add new flag ENABLE_STATIC_CRT for Windows

  - build: cmake: Support building nghttpx with systemd

  - third-party: Update neverbleed to fix memory leak

  - nghttpx: Fix bug that mruby is incorrectly shared
    between backends

  - nghttpx: Reconnect h1 backend if it lost connection
    before sending headers

  - nghttpx: Returns 408 if backend timed out before sending
    headers

  - nghttpx: Fix request stal

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1159003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166481"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nghttp2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-14-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-14-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-14-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libnghttp2_asio1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nghttp2-python-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-nghttp2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-nghttp2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libnghttp2-14-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnghttp2-14-debuginfo-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnghttp2-devel-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnghttp2_asio-devel-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnghttp2_asio1-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libnghttp2_asio1-debuginfo-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nghttp2-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nghttp2-debuginfo-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nghttp2-debugsource-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"nghttp2-python-debugsource-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-nghttp2-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"python3-nghttp2-debuginfo-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libnghttp2-14-32bit-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libnghttp2-14-32bit-debuginfo-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libnghttp2_asio1-32bit-1.40.0-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libnghttp2_asio1-32bit-debuginfo-1.40.0-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libnghttp2-14 / libnghttp2-14-debuginfo / libnghttp2-devel / etc");
}
