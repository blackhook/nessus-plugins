#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2016-1072.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(93435);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-8869");

  script_name(english:"openSUSE Security Update : ocaml (openSUSE-2016-1072)");
  script_summary(english:"Check for the openSUSE-2016-1072 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for ocaml fixes the following issue :

Security issue fixed :

  - CVE-2015-8869: Prevent buffer overflow and information
    leak. (bsc#977990)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=977990"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected ocaml packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-compiler-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-compiler-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-emacs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-ocamldoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-ocamldoc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-runtime-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ocaml-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2021 Tenable Network Security, Inc.");
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
if (release !~ "^(SUSE42\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.1", reference:"ocaml-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-compiler-libs-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-compiler-libs-devel-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-debuginfo-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-debugsource-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-emacs-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-ocamldoc-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-ocamldoc-debuginfo-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-rpm-macros-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-runtime-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-runtime-debuginfo-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-source-4.02.3-3.2") ) flag++;
if ( rpm_check(release:"SUSE42.1", reference:"ocaml-x11-4.02.3-3.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ocaml / ocaml-compiler-libs / ocaml-compiler-libs-devel / etc");
}
