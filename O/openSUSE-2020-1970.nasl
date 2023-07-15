#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1970.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143143);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/24");

  script_cve_id("CVE-2020-10592", "CVE-2020-10593", "CVE-2020-15572");

  script_name(english:"openSUSE Security Update : tor (openSUSE-2020-1970)");
  script_summary(english:"Check for the openSUSE-2020-1970 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for tor fixes the following issues :

Updating tor to a newer version in the respective codestream.

  - tor 0.3.5.12 :

  - Check channels+circuits on relays more thoroughly
    (TROVE-2020-005, boo#1178741)

  - Not affected by out-of-bound memory access
    (CVE-2020-15572, boo#1173979)

  - Fix DoS defenses on bridges with a pluggable transport

  - CVE-2020-10592: CPU consumption DoS and timing patterns
    (boo#1167013)

  - CVE-2020-10593: circuit padding memory leak
    (boo#1167014) 

  - tor 0.4.4.6

  - Check channels+circuits on relays more thoroughly
    (TROVE-2020-005, boo#1178741)

  - Fix a crash due to an out-of-bound memory access
    (CVE-2020-15572, boo#1173979)

  - Fix logrotate to not fail when tor is stopped
    (boo#1164275)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1164275"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173979"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178741"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected tor packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10592");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:tor-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"tor-0.3.5.12-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tor-debuginfo-0.3.5.12-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"tor-debugsource-0.3.5.12-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tor-0.4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tor-debuginfo-0.4.4.6-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"tor-debugsource-0.4.4.6-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tor / tor-debuginfo / tor-debugsource");
}
