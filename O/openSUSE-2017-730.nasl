#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-730.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101131);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521");

  script_name(english:"openSUSE Security Update : openvpn (openSUSE-2017-730)");
  script_summary(english:"Check for the openSUSE-2017-730 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openvpn fixes the following issues :

  - Some parts of the certificate-parsing code did not
    always clear all allocated memory. This would have
    allowed clients to leak a few bytes of memory for each
    connection attempt, thereby facilitating a (quite
    inefficient) DoS attack on the server. [bsc#1044947,
    CVE-2017-7521]

  - The ASN1 parsing code contained a bug that could have
    resulted in some buffers being free()d twice, and this
    issue could have potentially been triggered remotely by
    a VPN peer. [bsc#1044947, CVE-2017-7521]

  - If clients used a HTTP proxy with NTLM authentication, a
    man-in-the-middle attacker between client and proxy
    could cause the client to crash or disclose at most 96
    bytes of stack memory. The disclosed stack memory was
    likely to contain the proxy password. If the proxy
    password had not been reused, this was unlikely to
    compromise the security of the OpenVPN tunnel itself.
    Clients who did not use the --http-proxy option with
    ntlm2 authentication were not affected. [bsc#1044947,
    CVE-2017-7520]

  - It was possible to trigger an assertion by sending a
    malformed IPv6 packet. That issue could have been abused
    to remotely shutdown an openvpn server or client, if
    IPv6 and --mssfix were enabled and if the IPv6 networks
    used inside the VPN were known. [bsc#1044947,
    CVE-2017-7508]

This update was imported from the SUSE:SLE-12:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1044947"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected openvpn packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/30");
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
if (release !~ "^(SUSE42\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"openvpn-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-auth-pam-plugin-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-debuginfo-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-debugsource-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-devel-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-down-root-plugin-2.3.8-8.10.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"openvpn-down-root-plugin-debuginfo-2.3.8-8.10.1") ) flag++;

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
