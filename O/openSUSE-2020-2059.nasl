#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-2059.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(143304);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/02");

  script_cve_id("CVE-2015-4141", "CVE-2015-4142", "CVE-2015-4143", "CVE-2015-8041", "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088", "CVE-2018-14526", "CVE-2019-11555", "CVE-2019-13377", "CVE-2019-16275", "CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");

  script_name(english:"openSUSE Security Update : wpa_supplicant (openSUSE-2020-2059) (KRACK)");
  script_summary(english:"Check for the openSUSE-2020-2059 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for wpa_supplicant fixes the following issues :

Security issue fixed :

  - CVE-2019-16275: Fixed an AP mode PMF disconnection
    protection bypass (bsc#1150934).

Non-security issues fixed :

  - Enable SAE support (jsc#SLE-14992).

  - Limit P2P_DEVICE name to appropriate ifname size.

  - Fix wicked wlan (bsc#1156920)

  - Restore fi.epitest.hostap.WPASupplicant.service
    (bsc#1167331)

  - With v2.9 fi.epitest.hostap.WPASupplicant.service is
    obsolete (bsc#1167331)

  - Fix WLAN config on boot with wicked. (bsc#1166933)

  - Update to 2.9 release :

  - SAE changes

  - disable use of groups using Brainpool curves

  - improved protection against side channel attacks
    [https://w1.fi/security/2019-6/]

  - EAP-pwd changes

  - disable use of groups using Brainpool curves

  - allow the set of groups to be configured
    (eap_pwd_groups)

  - improved protection against side channel attacks
    [https://w1.fi/security/2019-6/]

  - fixed FT-EAP initial mobility domain association using
    PMKSA caching (disabled by default for backwards
    compatibility; can be enabled with
    ft_eap_pmksa_caching=1)

  - fixed a regression in OpenSSL 1.1+ engine loading

  - added validation of RSNE in (Re)Association Response
    frames

  - fixed DPP bootstrapping URI parser of channel list

  - extended EAP-SIM/AKA fast re-authentication to allow use
    with FILS

  - extended ca_cert_blob to support PEM format

  - improved robustness of P2P Action frame scheduling

  - added support for EAP-SIM/AKA using anonymous@realm
    identity

  - fixed Hotspot 2.0 credential selection based on roaming
    consortium to ignore credentials without a specific EAP
    method

  - added experimental support for EAP-TEAP peer (RFC 7170)

  - added experimental support for EAP-TLS peer with TLS
    v1.3

  - fixed a regression in WMM parameter configuration for a
    TDLS peer

  - fixed a regression in operation with drivers that
    offload 802.1X 4-way handshake

  - fixed an ECDH operation corner case with OpenSSL

  - SAE changes

  - added support for SAE Password Identifier

  - changed default configuration to enable only groups 19,
    20, 21 (i.e., disable groups 25 and 26) and disable all
    unsuitable groups completely based on REVmd changes

  - do not regenerate PWE unnecessarily when the AP uses the
    anti-clogging token mechanisms

  - fixed some association cases where both SAE and FT-SAE
    were enabled on both the station and the selected AP

  - started to prefer FT-SAE over SAE AKM if both are
    enabled

  - started to prefer FT-SAE over FT-PSK if both are enabled

  - fixed FT-SAE when SAE PMKSA caching is used

  - reject use of unsuitable groups based on new
    implementation guidance in REVmd (allow only FFC groups
    with prime >= 3072 bits and ECC groups with prime >=
    256)

  - minimize timing and memory use differences in PWE
    derivation [https://w1.fi/security/2019-1/]
    (CVE-2019-9494, bsc#1131868)

  - EAP-pwd changes

  - minimize timing and memory use differences in PWE
    derivation [https://w1.fi/security/2019-2/]
    (CVE-2019-9495, bsc#1131870)

  - verify server scalar/element
    [https://w1.fi/security/2019-4/] (CVE-2019-9497,
    CVE-2019-9498, CVE-2019-9499, bsc#1131874, bsc#1131872,
    bsc#1131871, bsc#1131644)

  - fix message reassembly issue with unexpected fragment
    [https://w1.fi/security/2019-5/] (CVE-2019-11555,
    bsc#1133640)

  - enforce rand,mask generation rules more strictly

  - fix a memory leak in PWE derivation

  - disallow ECC groups with a prime under 256 bits (groups
    25, 26, and 27)

  - SAE/EAP-pwd side-channel attack update
    [https://w1.fi/security/2019-6/] (CVE-2019-13377,
    bsc#1144443)

  - fixed CONFIG_IEEE80211R=y (FT) build without
    CONFIG_FILS=y

  - Hotspot 2.0 changes

  - do not indicate release number that is higher than the
    one AP supports

  - added support for release number 3

  - enable PMF automatically for network profiles created
    from credentials

  - fixed OWE network profile saving

  - fixed DPP network profile saving

  - added support for RSN operating channel validation
    (CONFIG_OCV=y and network profile parameter ocv=1)

  - added Multi-AP backhaul STA support

  - fixed build with LibreSSL

  - number of MKA/MACsec fixes and extensions

  - extended domain_match and domain_suffix_match to allow
    list of values

  - fixed dNSName matching in domain_match and
    domain_suffix_match when using wolfSSL

  - started to prefer FT-EAP-SHA384 over WPA-EAP-SUITE-B-192
    AKM if both are enabled

  - extended nl80211 Connect and external authentication to
    support SAE, FT-SAE, FT-EAP-SHA384

  - fixed KEK2 derivation for FILS+FT

  - extended client_cert file to allow loading of a chain of
    PEM encoded certificates

  - extended beacon reporting functionality

  - extended D-Bus interface with number of new properties

  - fixed a regression in FT-over-DS with mac80211-based
    drivers

  - OpenSSL: allow systemwide policies to be overridden

  - extended driver flags indication for separate 802.1X and
    PSK 4-way handshake offload capability

  - added support for random P2P Device/Interface Address
    use

  - extended PEAP to derive EMSK to enable use with ERP/FILS

  - extended WPS to allow SAE configuration to be added
    automatically for PSK (wps_cred_add_sae=1)

  - removed support for the old D-Bus interface
    (CONFIG_CTRL_IFACE_DBUS)

  - extended domain_match and domain_suffix_match to allow
    list of values

  - added a RSN workaround for misbehaving PMF APs that
    advertise IGTK/BIP KeyID using incorrect byte order

  - fixed PTK rekeying with FILS and FT

  - fixed WPA packet number reuse with replayed messages and
    key reinstallation [https://w1.fi/security/2017-1/]
    (CVE-2017-13077, CVE-2017-13078, CVE-2017-13079,
    CVE-2017-13080, CVE-2017-13081, CVE-2017-13082,
    CVE-2017-13086, CVE-2017-13087, CVE-2017-13088)

  - fixed unauthenticated EAPOL-Key decryption in
    wpa_supplicant [https://w1.fi/security/2018-1/]
    (CVE-2018-14526)

  - added support for FILS (IEEE 802.11ai) shared key
    authentication

  - added support for OWE (Opportunistic Wireless
    Encryption, RFC 8110; and transition mode defined by
    WFA)

  - added support for DPP (Wi-Fi Device Provisioning
    Protocol)

  - added support for RSA 3k key case with Suite B 192-bit
    level

  - fixed Suite B PMKSA caching not to update PMKID during
    each 4-way handshake

  - fixed EAP-pwd pre-processing with PasswordHashHash

  - added EAP-pwd client support for salted passwords

  - fixed a regression in TDLS prohibited bit validation

  - started to use estimated throughput to avoid undesired
    signal strength based roaming decision

  - MACsec/MKA :

  - new macsec_linux driver interface support for the Linux
    kernel macsec module

  - number of fixes and extensions

  - added support for external persistent storage of PMKSA
    cache (PMKSA_GET/PMKSA_ADD control interface commands;
    and MESH_PMKSA_GET/MESH_PMKSA_SET for the mesh case)

  - fixed mesh channel configuration pri/sec switch case

  - added support for beacon report

  - large number of other fixes, cleanup, and extensions

  - added support for randomizing local address for GAS
    queries (gas_rand_mac_addr parameter)

  - fixed EAP-SIM/AKA/AKA' ext auth cases within TLS tunnel

  - added option for using random WPS UUID (auto_uuid=1)

  - added SHA256-hash support for OCSP certificate matching

  - fixed EAP-AKA' to add AT_KDF into
    Synchronization-Failure

  - fixed a regression in RSN pre-authentication candidate
    selection

  - added option to configure allowed group management
    cipher suites (group_mgmt network profile parameter)

  - removed all PeerKey functionality

  - fixed nl80211 AP and mesh mode configuration regression
    with Linux 4.15 and newer

  - added ap_isolate configuration option for AP mode

  - added support for nl80211 to offload 4-way handshake
    into the driver

  - added support for using wolfSSL cryptographic library

  - SAE

  - added support for configuring SAE password separately of
    the WPA2 PSK/passphrase

  - fixed PTK and EAPOL-Key integrity and key-wrap algorithm
    selection for SAE; note: this is not backwards
    compatible, i.e., both the AP and station side
    implementations will need to be update at the same time
    to maintain interoperability

  - added support for Password Identifier

  - fixed FT-SAE PMKID matching

  - Hotspot 2.0

  - added support for fetching of Operator Icon Metadata
    ANQP-element

  - added support for Roaming Consortium Selection element

  - added support for Terms and Conditions

  - added support for OSEN connection in a shared RSN BSS

  - added support for fetching Venue URL information

  - added support for using OpenSSL 1.1.1

  - FT

  - disabled PMKSA caching with FT since it is not fully
    functional

  - added support for SHA384 based AKM

  - added support for BIP ciphers BIP-CMAC-256,
    BIP-GMAC-128, BIP-GMAC-256 in addition to previously
    supported BIP-CMAC-128

  - fixed additional IE inclusion in Reassociation Request
    frame when using FT protocol

  - Changed service-files for start after network
    (systemd-networkd).

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131644"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131868"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131870"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131871"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131872"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131874"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1133640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144443"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1150934"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1156920"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1166933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1167331"
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
    attribute:"see_also",
    value:"https://w1.fi/security/2017-1/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://w1.fi/security/2018-1/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://w1.fi/security/2019-1/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://w1.fi/security/2019-2/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://w1.fi/security/2019-4/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://w1.fi/security/2019-5/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://w1.fi/security/2019-6/]"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected wpa_supplicant packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9499");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wpa_supplicant-gui-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/30");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"wpa_supplicant-2.9-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wpa_supplicant-debuginfo-2.9-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wpa_supplicant-debugsource-2.9-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wpa_supplicant-gui-2.9-lp152.8.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wpa_supplicant-gui-debuginfo-2.9-lp152.8.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "wpa_supplicant / wpa_supplicant-debuginfo / etc");
}
