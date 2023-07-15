#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-717.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101128);
  script_version("3.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2016-6329", "CVE-2017-7478", "CVE-2017-7479");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"openSUSE Security Update : openvpn (openSUSE-2017-717) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for openvpn fixes the following issues :

  - CVE-2016-6329: Show which ciphers should no longer be
    used in openvpn --show-ciphers (bsc#995374)

  - CVE-2017-7478: openvpn: Authenticated user can DoS
    server by using a big payload in P_CONTROL (bsc#1038709)

  - CVE-2017-7479: openvpn: Denial of Service due to
    Exhaustion of Packet-ID counter (bsc#1038711)

  - Hardening measures found by internal audit (bsc#1038713)

This update was imported from the SUSE:SLE-12:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=995374");
  script_set_attribute(attribute:"solution", value:
"Update the affected openvpn packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-auth-pam-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-auth-pam-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-down-root-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:openvpn-down-root-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"openvpn-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-auth-pam-plugin-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-debuginfo-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-debugsource-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-devel-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-down-root-plugin-2.3.8-8.6.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-down-root-plugin-debuginfo-2.3.8-8.6.1") ) flag++;

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
