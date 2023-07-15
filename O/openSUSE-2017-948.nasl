#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-948.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102564);
  script_version("3.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-1000381", "CVE-2017-11499");

  script_name(english:"openSUSE Security Update : nodejs4 / nodejs6 (openSUSE-2017-948)");
  script_summary(english:"Check for the openSUSE-2017-948 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nodejs4 and nodejs6 fixes the following issues :

Security issues fixed :

  - CVE-2017-1000381: The c-ares function
    ares_parse_naptr_reply() could be triggered to read
    memory outside of the given input buffer if the passed
    in DNS response packet was crafted in a particular way.
    (bsc#1044946)

  - CVE-2017-11499: Disable V8 snapshots. The hashseed
    embedded in the snapshot is currently the same for all
    runs of the binary. This opens node up to collision
    attacks which could result in a Denial of Service. We
    have temporarily disabled snapshots until a more robust
    solution is found. (bsc#1048299)

Non-security fixes :

  - GCC 7 compilation fixes for v8 backported and add
    missing ICU59 headers (bsc#1041282)

  - New upstream LTS release 6.11.1

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.11.1

  - New upstream LTS release 6.11.0

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.11.0

  - New upstream LTS release 6.10.3

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.3

  - New upstream LTS release 6.10.2

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.2

  - New upstream LTS release 6.10.1

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.1

  - New upstream LTS release 6.10.0

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.0

  - New upstream LTS release 4.8.4

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.4

  - New upstream LTS release 4.8.3

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.3

  - New upstream LTS release 4.8.2

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.2

  - New upstream LTS release 4.8.1

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.1

  - New upstream LTS release 4.8.0

  - https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.0

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041282"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041283"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044946"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1048299"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6e76fcd6"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d586980d"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3af76941"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?2dc50043"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V4.md#4.8.4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cfaf99af"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a6929afa"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?971b1fd5"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.2
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?60de5186"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.10.3
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e6bb8119"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.11.0
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a27d290e"
  );
  # https://github.com/nodejs/node/blob/master/doc/changelogs/CHANGELOG_V6.md#6.11.1
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d5b218e3"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nodejs4 / nodejs6 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs4-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nodejs6-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:npm6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/16");
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

if ( rpm_check(release:"SUSE42.2", reference:"nodejs-common-1.0-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-4.8.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-debuginfo-4.8.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-debugsource-4.8.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"nodejs4-devel-4.8.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"npm4-4.8.4-5.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs-common-1.0-2.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-4.8.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-debuginfo-4.8.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-debugsource-4.8.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs4-devel-4.8.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-6.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-debuginfo-6.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-debugsource-6.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"nodejs6-devel-6.11.1-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"npm4-4.8.4-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"npm6-6.11.1-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs-common / nodejs4 / nodejs4-debuginfo / nodejs4-debugsource / etc");
}
