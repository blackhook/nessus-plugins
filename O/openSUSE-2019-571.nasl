#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-571.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123248);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-14055", "CVE-2018-14056");

  script_name(english:"openSUSE Security Update : znc (openSUSE-2019-571)");
  script_summary(english:"Check for the openSUSE-2019-571 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for znc fixes the following issues :

  - Update to version 1.7.1

  - CVE-2018-14055: non-admin user could gain admin
    privileges and shell access by injecting values into
    znc.conf (bnc#1101281)

  - CVE-2018-14056: path traversal in HTTP handler via ../
    in a web skin name. (bnc#1101280)

  - Update to version 1.7.0

  - Make ZNC UI translateable to different languages

  - Configs written before ZNC 0.206 can't be read anymore

  - Implement IRCv3.2 capabilities away-notify,
    account-notify, extended-join

  - Implement IRCv3.2 capabilities echo-message, cap-notify
    on the 'client side'

  - Update capability names as they are named in IRCv3.2:
    znc.in/server-time-iso&rarr;server-time,
    znc.in/batch&rarr;batch. Old names will continue working
    for a while, then will be removed in some future
    version.

  - Make ZNC request server-time from server when available

  - Add 'AuthOnlyViaModule' global/user setting

  - Stop defaulting real name to 'Got ZNC?'

  - Add SNI SSL client support

  - Add support for CIDR notation in allowed hosts list and
    in trusted proxy list

  - Add network-specific config for cert validation in
    addition to user-supplied fingerprints: TrustAllCerts,
    defaults to false, and TrustPKI, defaults to true.

  - Add /attach command for symmetry with /detach. Unlike
    /join it allows wildcards.

  - Update to version 1.6.6 :

  - Fix use-after-free in znc --makepem. It was broken for a
    long time, but started segfaulting only now. This is a
    useability fix, not a security fix, because self-signed
    (or signed by a CA) certificates can be created without
    using --makepem, and then combined into znc.pem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101280"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101281"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected znc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14056");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-python3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-python3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-tcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:znc-tcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/27");
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

if ( rpm_check(release:"SUSE15.0", reference:"znc-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-debuginfo-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-debugsource-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-devel-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-lang-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-perl-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-perl-debuginfo-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-python3-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-python3-debuginfo-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-tcl-1.7.1-lp150.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"znc-tcl-debuginfo-1.7.1-lp150.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "znc / znc-debuginfo / znc-debugsource / znc-devel / znc-lang / etc");
}
