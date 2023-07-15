#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2014-537.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(77660);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2014-3618");
  script_bugtraq_id(69573);

  script_name(english:"openSUSE Security Update : procmail (openSUSE-SU-2014:1114-1)");
  script_summary(english:"Check for the openSUSE-2014-537 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"procmail was updated to fix a heap-overflow in procmail's formail
utility when processing specially crafted email headers (bnc#894999,
CVE-2014-3618)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=894999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.opensuse.org/opensuse-updates/2014-09/msg00016.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected procmail packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procmail-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:procmail-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:12.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:13.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE12\.3|SUSE13\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "12.3 / 13.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE12.3", reference:"procmail-3.22-260.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"procmail-debuginfo-3.22-260.6.1") ) flag++;
if ( rpm_check(release:"SUSE12.3", reference:"procmail-debugsource-3.22-260.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"procmail-3.22-264.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"procmail-debuginfo-3.22-264.6.1") ) flag++;
if ( rpm_check(release:"SUSE13.1", reference:"procmail-debugsource-3.22-264.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "procmail");
}
