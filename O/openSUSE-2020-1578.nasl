#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1578.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141158);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/07");

  script_cve_id("CVE-2020-8927");

  script_name(english:"openSUSE Security Update : brotli (openSUSE-2020-1578)");
  script_summary(english:"Check for the openSUSE-2020-1578 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for brotli fixes the following issues :

brotli was updated to 1.0.9 :

  - CVE-2020-8927: Fix integer overflow when input chunk is
    longer than 2GiB [boo#1175825]

  - `brotli -v` now reports raw / compressed size

  - decoder: minor speed / memory usage improvements

  - encoder: fix rare access to uninitialized data in
    ring-buffer"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175825"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected brotli packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brotli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:brotli-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotli-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlicommon1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlicommon1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlicommon1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlicommon1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlidec1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlidec1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlidec1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlidec1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlienc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlienc1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlienc1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libbrotlienc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/29");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"brotli-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"brotli-debuginfo-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"brotli-debugsource-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotli-devel-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotlicommon1-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotlicommon1-debuginfo-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotlidec1-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotlidec1-debuginfo-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotlienc1-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libbrotlienc1-debuginfo-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbrotlicommon1-32bit-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbrotlicommon1-32bit-debuginfo-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbrotlidec1-32bit-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbrotlidec1-32bit-debuginfo-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbrotlienc1-32bit-1.0.9-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libbrotlienc1-32bit-debuginfo-1.0.9-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "brotli / brotli-debuginfo / brotli-debugsource / libbrotli-devel / etc");
}
