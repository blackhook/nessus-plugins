#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-937.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102556);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-11103", "CVE-2017-6594");

  script_name(english:"openSUSE Security Update : libheimdal (openSUSE-2017-937) (Orpheus' Lyre)");
  script_summary(english:"Check for the openSUSE-2017-937 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libheimdal fixes the following issues :

  - Fix CVE-2017-11103: Orpheus' Lyre KDC-REP service name
    validation. This is a critical vulnerability. In
    _krb5_extract_ticket() the KDC-REP service name must be
    obtained from encrypted version stored in 'enc_part'
    instead of the unencrypted version stored in 'ticket'.
    Use of the unecrypted version provides an opportunity
    for successful server impersonation and other attacks.
    Identified by Jeffrey Altman, Viktor Duchovni and Nico
    Williams. See https://www.orpheus-lyre.info/ for more
    details. (bsc#1048278)

  - Fix CVE-2017-6594: transit path validation inadvertently
    caused the previous hop realm to not be added to the
    transit path of issued tickets. This may, in some cases,
    enable bypass of capath policy in Heimdal versions 1.5
    through 7.2. Note, this may break sites that rely on the
    bug. With the bug some incomplete [capaths] worked, that
    should not have. These may now break authentication in
    some cross-realm configurations."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048278"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.orpheus-lyre.info/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libheimdal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 Tenable Network Security, Inc.");
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

if ( rpm_check(release:"SUSE42.2", reference:"libheimdal-7.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libheimdal-debuginfo-7.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libheimdal-debugsource-7.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"libheimdal-devel-7.4.0-2.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-7.4.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-debuginfo-7.4.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-debugsource-7.4.0-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-devel-7.4.0-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libheimdal / libheimdal-debuginfo / libheimdal-debugsource / etc");
}
