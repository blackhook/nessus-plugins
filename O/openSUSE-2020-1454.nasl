#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1454.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(140684);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/09/23");

  script_cve_id("CVE-2020-15953");

  script_name(english:"openSUSE Security Update : libetpan (openSUSE-2020-1454)");
  script_summary(english:"Check for the openSUSE-2020-1454 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for libetpan fixes the following issues :

Update to 1.9.4 (boo#1174579, CVE-2020-15953) :

  - Bugfixes on QUOTA

  - Varios warning fixes & build fixes 

Update to version 1.9.3

  - Added IMAP CLIENTID / SMTP CLIENTID support

  - Use Cyrus SASL 2.1.27

Update to version 1.9.2

  - Support of TLS SNI

  - LMDB for cache DB

  - Fixed build with recent versions of curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174579"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected libetpan packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetpan-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetpan-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetpan20");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libetpan20-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/21");
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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libetpan-debugsource-1.9.4-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libetpan-devel-1.9.4-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libetpan20-1.9.4-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libetpan20-debuginfo-1.9.4-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libetpan-debugsource / libetpan-devel / libetpan20 / etc");
}
