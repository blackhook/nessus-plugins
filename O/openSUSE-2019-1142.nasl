#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1142.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123772);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-6196", "CVE-2018-6197", "CVE-2018-6198");

  script_name(english:"openSUSE Security Update : w3m (openSUSE-2019-1142)");
  script_summary(english:"Check for the openSUSE-2019-1142 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for w3m fixes the following issues :

Security issues fixed :

  - CVE-2018-6196: Prevent infinite recursion in
    HTMLlineproc0 caused by the feed_table_block_tag
    function which did not prevent a negative indent value
    (bsc#1077559)

  - CVE-2018-6197: Prevent NULL pointer dereference in
    formUpdateBuffer (bsc#1077568)

  - CVE-2018-6198: w3m did not properly handle temporary
    files when the ~/.w3m directory is unwritable, which
    allowed a local attacker to craft a symlink attack to
    overwrite arbitrary files (bsc#1077572)

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077559"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077568"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1077572"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected w3m packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-6198");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-inline-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:w3m-inline-image-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/01/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/05");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"w3m-0.5.3.git20161120-164.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"w3m-debuginfo-0.5.3.git20161120-164.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"w3m-debugsource-0.5.3.git20161120-164.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"w3m-inline-image-0.5.3.git20161120-164.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"w3m-inline-image-debuginfo-0.5.3.git20161120-164.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "w3m / w3m-debuginfo / w3m-debugsource / w3m-inline-image / etc");
}
