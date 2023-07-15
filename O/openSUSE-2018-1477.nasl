#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1477.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119295);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-15473");

  script_name(english:"openSUSE Security Update : openssh (openSUSE-2018-1477)");
  script_summary(english:"Check for the openSUSE-2018-1477 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openssh fixes the following issues :

Following security issues have been fixed :

  - CVE-2018-15473: OpenSSH was prone to a user existance
    oracle vulnerability due to not delaying bailout for an
    invalid authenticating user until after the packet
    containing the request has been fully parsed, related to
    auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.
    (bsc#1105010)

The following non-security issues were fixed :

  - Stop leaking File descriptors (bsc#964336)

  - sftp-client.c returns wrong error code upon failure
    [bsc#1091396]

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091396"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1105010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=964336"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openssh packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-askpass-gnome-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-cavs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-cavs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-fips");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openssh-helpers-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"openssh-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-askpass-gnome-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-askpass-gnome-debuginfo-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-cavs-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-cavs-debuginfo-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-debuginfo-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-debugsource-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-fips-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-helpers-7.2p2-25.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"openssh-helpers-debuginfo-7.2p2-25.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssh-askpass-gnome / openssh-askpass-gnome-debuginfo / openssh / etc");
}
