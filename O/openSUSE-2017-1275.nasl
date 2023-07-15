#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1275.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104614);
  script_version("3.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-15535");

  script_name(english:"openSUSE Security Update : mongodb (openSUSE-2017-1275)");
  script_summary(english:"Check for the openSUSE-2017-1275 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for mongodb 3.4.10 fixes the following issues :

Security issues fixed :

  - CVE-2017-15535: MongoDB 3.4.x before 3.4.10, and
    3.5.x-development, has a disabled-by-default
    configuration setting, networkMessageCompressors (aka
    wire protocol compression), which exposes a
    vulnerability when enabled that could be exploited by a
    malicious attacker to deny service or modify memory.
    (boo#1065956)

Bug fixes :

  - See release-notes for 3.4.4 - 3.4.10 changes.

  - https://docs.mongodb.com/manual/release-notes/3.4-changelog/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065956"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.mongodb.com/manual/release-notes/3.4-changelog/"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mongodb packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-mongoperf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-mongoperf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-mongos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-mongos-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:mongodb-shell-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/16");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"mongodb-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-debugsource-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-mongoperf-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-mongoperf-debuginfo-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-mongos-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-mongos-debuginfo-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-server-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-server-debuginfo-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-shell-3.4.10-3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"mongodb-shell-debuginfo-3.4.10-3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mongodb / mongodb-debugsource / mongodb-mongoperf / etc");
}
