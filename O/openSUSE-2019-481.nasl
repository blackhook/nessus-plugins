#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-481.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123199);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-11218", "CVE-2018-11219");

  script_name(english:"openSUSE Security Update : redis (openSUSE-2019-481)");
  script_summary(english:"Check for the openSUSE-2019-481 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for redis to 4.0.10 fixes the following issues :

These security issues were fixed :

  - CVE-2018-11218: Prevent heap corruption vulnerability in
    cmsgpack (bsc#1097430).

  - CVE-2018-11219: Prevent integer overflow in Lua
    scripting (bsc#1097768).

For Leap 42.3 and openSUSE SLE 12 backports this is a jump from 4.0.6.
For additional details please see

- https://raw.githubusercontent.com/antirez/redis/4.0.9/00-RELEASENOTES

- https://raw.githubusercontent.com/antirez/redis/4.0.8/00-RELEASENOTES

- https://raw.githubusercontent.com/antirez/redis/4.0.7/00-RELEASENOTES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097430"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097768"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://raw.githubusercontent.com/antirez/redis/4.0.7/00-RELEASENOTES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://raw.githubusercontent.com/antirez/redis/4.0.8/00-RELEASENOTES"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://raw.githubusercontent.com/antirez/redis/4.0.9/00-RELEASENOTES"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected redis packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:redis-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/06/17");
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

if ( rpm_check(release:"SUSE15.0", reference:"redis-4.0.10-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"redis-debuginfo-4.0.10-lp150.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"redis-debugsource-4.0.10-lp150.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redis / redis-debuginfo / redis-debugsource");
}
