#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1825.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(142583);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/09");

  script_cve_id("CVE-2020-25654");

  script_name(english:"openSUSE Security Update : pacemaker (openSUSE-2020-1825)");
  script_summary(english:"Check for the openSUSE-2020-1825 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for pacemaker fixes the following issues :

  - executor: restrict certain IPC requests to Pacemaker
    daemons (CVE-2020-25654, bsc#1177916)

  - extra: add vim modelines to agents

  - extra: quote shell variables in agent code where
    appropriate (bsc#1175557)

  - extra: remove trailing whitespace from agent code

  - extra: update agent boilerplate (copyright/license
    notices)

  - extra: use 4-space indents in resource agent code

  - extra: use ':=' where appropriate in agent code

  - fencer: restrict certain IPC requests to privileged
    users (CVE-2020-25654, bsc#1177916)

  - move bcond_with/without up front for e.g. pcmk_release

  - pacemakerd: ignore shutdown requests from unprivileged
    users (CVE-2020-25654, bsc#1177916)

  - rpm: add spec option for enabling CIB secrets

  - rpm: put user-configurable items at top of spec

  - rpm: use the user/group ID 90 for haclient/hacluster to
    be consistent with cluster-glue (bsc#1167171)

This update was imported from the SUSE:SLE-15-SP1:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175557"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177916"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected pacemaker packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpacemaker3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cli-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-cts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:pacemaker-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/06");
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

if ( rpm_check(release:"SUSE15.1", reference:"libpacemaker-devel-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpacemaker3-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"libpacemaker3-debuginfo-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-cli-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-cli-debuginfo-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-cts-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-debuginfo-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-debugsource-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-remote-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"pacemaker-remote-debuginfo-2.0.1+20190417.13d370ca9-lp151.2.16.4") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpacemaker-devel / libpacemaker3 / libpacemaker3-debuginfo / etc");
}
