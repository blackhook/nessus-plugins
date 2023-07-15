#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1314.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(118486);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-10887", "CVE-2018-10888", "CVE-2018-11235", "CVE-2018-15501", "CVE-2018-8099");

  script_name(english:"openSUSE Security Update : libgit2 (openSUSE-2018-1314)");
  script_summary(english:"Check for the openSUSE-2018-1314 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libgit2 fixes the following issues :

  - CVE-2018-8099: Fixed possible denial of service attack
    via different vectors by not being able to differentiate
    between these status codes (bsc#1085256).

  - CVE-2018-11235: With a crafted .gitmodules file, a
    malicious project can execute an arbitrary script on a
    machine that runs 'git clone --recurse-submodules'
    because submodule 'names' are obtained from this file,
    and then appended to $GIT_DIR/modules, leading to
    directory traversal with '../' in a name. Finally,
    post-checkout hooks from a submodule are executed,
    bypassing the intended design in which hooks are not
    obtained from a remote server. (bsc#1095219)

  - CVE-2018-10887: It has been discovered that an
    unexpected sign extension in git_delta_apply function in
    delta.c file may have lead to an integer overflow which
    in turn leads to an out of bound read, allowing to read
    before the base object. An attacker could have used this
    flaw to leak memory addresses or cause a Denial of
    Service. (bsc#1100613)

  - CVE-2018-10888: A missing check in git_delta_apply
    function in delta.c file, may lead to an out-of-bound
    read while reading a binary delta file. An attacker may
    use this flaw to cause a Denial of Service.
    (bsc#1100612)

  - CVE-2018-15501: A remote attacker can send a crafted
    smart-protocol 'ng' packet that lacks a '\0' byte to
    trigger an out-of-bounds read that leads to DoS.
    (bsc#1104641)

This update was imported from the SUSE:SLE-12-SP2:Update update
project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085256"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095219"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104641"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libgit2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-24-debuginfo-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libgit2-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/29");
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

if ( rpm_check(release:"SUSE42.3", reference:"libgit2-24-0.24.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgit2-24-debuginfo-0.24.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgit2-debugsource-0.24.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libgit2-devel-0.24.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgit2-24-32bit-0.24.1-10.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", cpu:"x86_64", reference:"libgit2-24-debuginfo-32bit-0.24.1-10.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgit2-24 / libgit2-24-32bit / libgit2-24-debuginfo / etc");
}
