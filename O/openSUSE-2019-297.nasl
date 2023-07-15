#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-297.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122662);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-1238");

  script_name(english:"openSUSE Security Update : amavisd-new (openSUSE-2019-297)");
  script_summary(english:"Check for the openSUSE-2019-297 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for amavisd-new fixes the following issues :

Security issue fixed :

  - CVE-2016-1238: Workedaround a perl vulnerability by
    removing a trailing dot element from
    @INC&#9;(bsc#987887).

Other issues addressed :

  - update to version 2.11.1 (bsc#1123389).

  - amavis-services: bumping up syslog level from LOG_NOTICE
    to LOG_ERR for a message 'PID <pid> went away', and
    removed redundant newlines from some log messages

  - avoid warning messages 'Use of uninitialized value in
    subroutine entry' in Encode::MIME::Header when the
    $check argument is undefined 

  - @sa_userconf_maps has been extended to allow loading of
    per-recipient (or per-policy bank, or global)
    SpamAssassin configuration set from LDAP. For
    consistency with SQL a @sa_userconf_maps entry prefixed
    with 'ldap:' will load SpamAssassin configuration set
    using the load_scoreonly_ldap() method.

  - add some Sanesecurity.Foxhole false positives to the
    default list @virus_name_to_spam_score_maps

  - update amavis-milter to version 2.6.1 :

  - Fixed a bug when creating amavisd-new policy bank names

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1123389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=987887"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected amavisd-new packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amavisd-new");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amavisd-new-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:amavisd-new-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"amavisd-new-2.11.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"amavisd-new-debuginfo-2.11.1-lp150.5.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"amavisd-new-debugsource-2.11.1-lp150.5.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "amavisd-new / amavisd-new-debuginfo / amavisd-new-debugsource");
}
