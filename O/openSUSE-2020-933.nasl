#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-933.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(138725);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2020-1967");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"openSUSE Security Update : rust / rust-cbindgen (openSUSE-2020-933)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for rust, rust-cbindgen fixes the following issues :

  - Updated openssl-src to 1.1.1g for CVE-2020-1967.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1154817");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173202");
  script_set_attribute(attribute:"solution", value:
"Update the affected rust / rust-cbindgen packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cargo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:clippy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-analysis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-cbindgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-gdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rust-std-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rustfmt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

if ( rpm_check(release:"SUSE15.1", reference:"cargo-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"clippy-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rls-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rust-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rust-analysis-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rust-gdb-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rust-src-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rust-std-static-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"rustfmt-1.43.1-lp151.5.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"rust-cbindgen-0.14.1-lp151.8.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "rust-cbindgen / cargo / clippy / rls / rust / rust-analysis / etc");
}
