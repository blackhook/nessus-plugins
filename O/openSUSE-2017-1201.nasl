#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2017-1201.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104237);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2015-1863", "CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-4144", "CVE-2015-4145", "CVE-2015-5314", "CVE-2016-4476", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13087", "CVE-2017-13088");
  script_xref(name:"IAVA", value:"2017-A-0310");

  script_name(english:"openSUSE Security Update : hostapd (openSUSE-2017-1201) (KRACK)");
  script_summary(english:"Check for the openSUSE-2017-1201 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for hostapd fixes the following issues :

  - Fix KRACK attacks on the AP side (boo#1063479,
    CVE-2017-13078, CVE-2017-13079, CVE-2017-13080,
    CVE-2017-13081, CVE-2017-13087, CVE-2017-13088) :

Hostap was updated to upstream release 2.6

  - fixed EAP-pwd last fragment validation
    [http://w1.fi/security/2015-7/] (CVE-2015-5314)

  - fixed WPS configuration update vulnerability with
    malformed passphrase [http://w1.fi/security/2016-1/]
    (CVE-2016-4476)

  - extended channel switch support for VHT bandwidth
    changes

  - added support for configuring new ANQP-elements with
    anqp_elem=<InfoID>:<hexdump of payload>

  - fixed Suite B 192-bit AKM to use proper PMK length
    (note: this makes old releases incompatible with the
    fixed behavior)

  - added no_probe_resp_if_max_sta=1 parameter to disable
    Probe Response frame sending for not-associated STAs if
    max_num_sta limit has been reached

  - added option (-S as command line argument) to request
    all interfaces to be started at the same time

  - modified rts_threshold and fragm_threshold configuration
    parameters to allow -1 to be used to disable
    RTS/fragmentation

  - EAP-pwd: added support for Brainpool Elliptic Curves
    (with OpenSSL 1.0.2 and newer)

  - fixed EAPOL reauthentication after FT protocol run

  - fixed FTIE generation for 4-way handshake after FT
    protocol run

  - fixed and improved various FST operations

  - TLS server

  - support SHA384 and SHA512 hashes

  - support TLS v1.2 signature algorithm with SHA384 and
    SHA512

  - support PKCS #5 v2.0 PBES2

  - support PKCS #5 with PKCS #12 style key decryption

  - minimal support for PKCS #12

  - support OCSP stapling (including ocsp_multi)

  - added support for OpenSSL 1.1 API changes

  - drop support for OpenSSL 0.9.8

  - drop support for OpenSSL 1.0.0

  - EAP-PEAP: support fast-connect crypto binding

  - RADIUS

  - fix Called-Station-Id to not escape SSID

  - add Event-Timestamp to all Accounting-Request packets

  - add Acct-Session-Id to Accounting-On/Off

  - add Acct-Multi-Session-Id ton Access-Request packets

  - add Service-Type (= Frames)

  - allow server to provide PSK instead of passphrase for
    WPA-PSK Tunnel_password case

  - update full message for interim accounting updates

  - add Acct-Delay-Time into Accounting messages

  - add require_message_authenticator configuration option
    to require CoA/Disconnect-Request packets to be
    authenticated

  - started to postpone WNM-Notification frame sending by
    100 ms so that the STA has some more time to configure
    the key before this frame is received after the 4-way
    handshake

  - VHT: added interoperability workaround for 80+80 and 160
    MHz channels

  - extended VLAN support (per-STA vif, etc.)

  - fixed PMKID derivation with SAE

  - nl80211

  - added support for full station state operations

  - fix IEEE 802.1X/WEP EAP reauthentication and rekeying to
    use unencrypted EAPOL frames

  - added initial MBO support; number of extensions to WNM
    BSS Transition Management

  - added initial functionality for location related
    operations

  - added assocresp_elements parameter to allow vendor
    specific elements to be added into (Re)Association
    Response frames

  - improved Public Action frame addressing

  - use Address 3 = wildcard BSSID in GAS response if a
    query from an unassociated STA used that address

  - fix TX status processing for Address 3 = wildcard BSSID

  - add gas_address3 configuration parameter to control
    Address 3 behavior

  - added command line parameter -i to override interface
    parameter in hostapd.conf

  - added command completion support to hostapd_cli

  - added passive client taxonomy determination
    (CONFIG_TAXONOMY=y compile option and 'SIGNATURE <addr>'
    control interface command)

  - number of small fixes

hostapd was updated to upstream release 2.5

  - (CVE-2015-1863) is fixed in upstream release 2.5

  - fixed WPS UPnP vulnerability with HTTP chunked transfer
    encoding [http://w1.fi/security/2015-2/] (CVE-2015-4141
    boo#930077)

  - fixed WMM Action frame parser
    [http://w1.fi/security/2015-3/] (CVE-2015-4142
    boo#930078)

  - fixed EAP-pwd server missing payload length validation
    [http://w1.fi/security/2015-4/] (CVE-2015-4143,
    CVE-2015-4144, CVE-2015-4145, boo#930079)

  - fixed validation of WPS and P2P NFC NDEF record payload
    length [http://w1.fi/security/2015-5/]

  - nl80211 :

  - fixed vendor command handling to check OUI properly

  - fixed hlr_auc_gw build with OpenSSL

  - hlr_auc_gw: allow Milenage RES length to be reduced

  - disable HT for a station that does not support WMM/QoS

  - added support for hashed password (NtHash) in EAP-pwd
    server

  - fixed and extended dynamic VLAN cases

  - added EAP-EKE server support for deriving Session-Id

  - set Acct-Session-Id to a random value to make it more
    likely to be unique even if the device does not have a
    proper clock

  - added more 2.4 GHz channels for 20/40 MHz HT co-ex scan

  - modified SAE routines to be more robust and PWE
    generation to be stronger against timing attacks

  - added support for Brainpool Elliptic Curves with SAE

  - increases maximum value accepted for cwmin/cwmax

  - added support for CCMP-256 and GCMP-256 as group ciphers
    with FT

  - added Fast Session Transfer (FST) module

  - removed optional fields from RSNE when using FT with PMF
    (workaround for interoperability issues with iOS 8.4)

  - added EAP server support for TLS session resumption

  - fixed key derivation for Suite B 192-bit AKM (this
    breaks compatibility with the earlier version)

  - added mechanism to track unconnected stations and do
    minimal band steering

  - number of small fixes"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2015-2/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2015-3/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2015-4/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2015-5/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2015-7/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2016-1/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063479"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930077"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=930079"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hostapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hostapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hostapd-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/30");
  script_set_attribute(attribute:"stig_severity", value:"II");
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
if (release !~ "^(SUSE42\.2|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.2 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.2", reference:"hostapd-2.6-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"hostapd-debuginfo-2.6-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.2", reference:"hostapd-debugsource-2.6-5.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"hostapd-2.6-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"hostapd-debuginfo-2.6-8.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"hostapd-debugsource-2.6-8.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "hostapd / hostapd-debuginfo / hostapd-debugsource");
}
