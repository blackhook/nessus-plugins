#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-734.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(149641);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/24");

  script_cve_id("CVE-2018-7544", "CVE-2020-11810", "CVE-2020-15078");

  script_name(english:"openSUSE Security Update : openvpn (openSUSE-2021-734)");
  script_summary(english:"Check for the openSUSE-2021-734 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for openvpn fixes the following issues :

  - CVE-2020-15078: Fixed authentication bypass with
    deferred authentication (bsc#1185279).

  - CVE-2020-11810: Fixed race condition between allocating
    peer-id and initializing data channel key (bsc#1169925).

  - CVE-2018-7544: Fixed cross-protocol scripting issue that
    was discovered in the management interface
    (bsc#1085803).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1169925"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1185279"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected openvpn packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7544");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-auth-pam-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-auth-pam-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-down-root-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-down-root-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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

if ( rpm_check(release:"SUSE15.2", reference:"openvpn-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-auth-pam-plugin-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-auth-pam-plugin-debuginfo-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-debuginfo-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-debugsource-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-devel-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-down-root-plugin-2.4.3-lp152.6.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"openvpn-down-root-plugin-debuginfo-2.4.3-lp152.6.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn / openvpn-auth-pam-plugin / etc");
}
