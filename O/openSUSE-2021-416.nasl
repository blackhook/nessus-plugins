#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-416.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(147844);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/19");

  script_cve_id("CVE-2021-26675", "CVE-2021-26676");

  script_name(english:"openSUSE Security Update : connman (openSUSE-2021-416)");
  script_summary(english:"Check for the openSUSE-2021-416 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for connman fixes the following issues :

Update to 1.39 (boo#1181751) :

  - Fix issue with scanning state synchronization and iwd.

  - Fix issue with invalid key with 4-way handshake
    offloading.

  - Fix issue with DNS proxy length checks to prevent buffer
    overflow. (CVE-2021-26675)

  - Fix issue with DHCP leaking stack data via uninitialized
    variable. (CVE-2021-26676)

Update to 1.38 :

  - Fix issue with online check on IP address update.

  - Fix issue with OpenVPN and encrypted private keys.

  - Fix issue with finishing of VPN connections.

  - Add support for updated stable iwd APIs.

  - Add support for WireGuard networks.

Update to 1.37 :

  - Fix issue with handling invalid gateway addresses.

  - Fix issue with handling updates of default gateway.

  - Fix issue with DHCP servers that require broadcast flag.

  - Add support for option to use gateways as time servers.

  - Add support for option to select default technology.

  - Add support for Address Conflict Detection (ACD).

  - Add support for IPv6 iptables management.

Change in 1.36 :

  - Fix issue with DNS short response on error handling.

  - Fix issue with handling incoming DNS requests.

  - Fix issue with handling empty timeserver list.

  - Fix issue with incorrect DHCP byte order.

  - Fix issue with AllowDomainnameUpdates handling.

  - Fix issue with IPv4 link-local IP conflict error.

  - Fix issue with handling WISPr over TLS connections.

  - Fix issue with WiFi background scanning handling.

  - Fix issue with WiFi disconnect+connect race condition.

  - Fix issue with WiFi scanning and tethering operation.

  - Fix issue with WiFi security change handling.

  - Fix issue with missing signal for WPS changes.

  - Fix issue with online check retry handling.

  - Add support for systemd-resolved backend.

  - Add support for mDNS configuration setup."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1181751"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected connman packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-nmcompat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-hh2serial-gps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-hh2serial-gps-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-iospm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-iospm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-l2tp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-l2tp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-openconnect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-openconnect-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-polkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-pptp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-pptp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-tist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-tist-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-vpnc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-vpnc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-wireguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-plugin-wireguard-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:connman-test");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/17");
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

if ( rpm_check(release:"SUSE15.2", reference:"connman-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-client-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-client-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-debugsource-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-devel-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-nmcompat-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-hh2serial-gps-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-hh2serial-gps-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-iospm-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-iospm-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-l2tp-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-l2tp-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-openconnect-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-openconnect-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-openvpn-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-openvpn-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-polkit-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-pptp-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-pptp-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-tist-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-tist-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-vpnc-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-vpnc-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-wireguard-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-plugin-wireguard-debuginfo-1.39-lp152.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"connman-test-1.39-lp152.3.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "connman / connman-client / connman-client-debuginfo / etc");
}
