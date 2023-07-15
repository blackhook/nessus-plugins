#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-222.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(133758);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/02/20");

  script_cve_id("CVE-2017-13082", "CVE-2019-9494", "CVE-2019-9495", "CVE-2019-9496", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");

  script_name(english:"openSUSE Security Update : hostapd (openSUSE-2020-222) (KRACK)");
  script_summary(english:"Check for the openSUSE-2020-222 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for hostapd fixes the following issues :

hostapd was updated to version 2.9 :

  - SAE changes

  - disable use of groups using Brainpool curves

  - improved protection against side channel attacks
    [https://w1.fi/security/2019-6/]

  - EAP-pwd changes

  - disable use of groups using Brainpool curves

  - improved protection against side channel attacks
    [https://w1.fi/security/2019-6/]

  - fixed FT-EAP initial mobility domain association using
    PMKSA caching

  - added configuration of airtime policy

  - fixed FILS to and RSNE into (Re)Association Response
    frames

  - fixed DPP bootstrapping URI parser of channel list

  - added support for regulatory WMM limitation (for ETSI)

  - added support for MACsec Key Agreement using IEEE
    802.1X/PSK

  - added experimental support for EAP-TEAP server (RFC
    7170)

  - added experimental support for EAP-TLS server with TLS
    v1.3

  - added support for two server certificates/keys (RSA/ECC)

  - added AKMSuiteSelector into 'STA <addr>' control
    interface data to determine with AKM was used for an
    association

  - added eap_sim_id parameter to allow EAP-SIM/AKA server
    pseudonym and fast reauthentication use to be disabled

  - fixed an ECDH operation corner case with OpenSSL

Update to version 2.8

  - SAE changes

  - added support for SAE Password Identifier

  - changed default configuration to enable only group 19
    (i.e., disable groups 20, 21, 25, 26 from default
    configuration) and disable all unsuitable groups
    completely based on REVmd changes

  - improved anti-clogging token mechanism and SAE
    authentication frame processing during heavy CPU load;
    this mitigates some issues with potential DoS attacks
    trying to flood an AP with large number of SAE messages

  - added Finite Cyclic Group field in status code 77
    responses

  - reject use of unsuitable groups based on new
    implementation guidance in REVmd (allow only FFC groups
    with prime >= 3072 bits and ECC groups with prime >=
    256)

  - minimize timing and memory use differences in PWE
    derivation [https://w1.fi/security/2019-1/]
    (CVE-2019-9494)

  - fixed confirm message validation in error cases
    [https://w1.fi/security/2019-3/] (CVE-2019-9496)

  - EAP-pwd changes

  - minimize timing and memory use differences in PWE
    derivation [https://w1.fi/security/2019-2/]
    (CVE-2019-9495)

  - verify peer scalar/element
    [https://w1.fi/security/2019-4/] (CVE-2019-9497 and
    CVE-2019-9498)

  - fix message reassembly issue with unexpected fragment
    [https://w1.fi/security/2019-5/]

  - enforce rand,mask generation rules more strictly

  - fix a memory leak in PWE derivation

  - disallow ECC groups with a prime under 256 bits (groups
    25, 26, and 27)

  - Hotspot 2.0 changes

  - added support for release number 3

  - reject release 2 or newer association without PMF

  - added support for RSN operating channel validation
    (CONFIG_OCV=y and configuration parameter ocv=1)

  - added Multi-AP protocol support

  - added FTM responder configuration

  - fixed build with LibreSSL

  - added FT/RRB workaround for short Ethernet frame padding

  - fixed KEK2 derivation for FILS+FT

  - added RSSI-based association rejection from OCE

  - extended beacon reporting functionality

  - VLAN changes

  - allow local VLAN management with remote RADIUS
    authentication

  - add WPA/WPA2 passphrase/PSK -based VLAN assignment

  - OpenSSL: allow systemwide policies to be overridden

  - extended PEAP to derive EMSK to enable use with ERP/FILS

  - extended WPS to allow SAE configuration to be added
    automatically for PSK (wps_cred_add_sae=1)

  - fixed FT and SA Query Action frame with
    AP-MLME-in-driver cases

  - OWE: allow Diffie-Hellman Parameter element to be
    included with DPP in preparation for DPP protocol
    extension

  - RADIUS server: started to accept ERP keyName-NAI as user
    identity automatically without matching EAP database
    entry

  - fixed PTK rekeying with FILS and FT

wpa_supplicant :

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
    (CVE-2019-9494)

  - EAP-pwd changes

  - minimize timing and memory use differences in PWE
    derivation [https://w1.fi/security/2019-2/]
    (CVE-2019-9495)

  - verify server scalar/element
    [https://w1.fi/security/2019-4/] (CVE-2019-9499)

  - fix message reassembly issue with unexpected fragment
    [https://w1.fi/security/2019-5/]

  - enforce rand,mask generation rules more strictly

  - fix a memory leak in PWE derivation

  - disallow ECC groups with a prime under 256 bits (groups
    25, 26, and 27)

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

  - Enabled CLI editing and history support.

Update to version 2.7

  - fixed WPA packet number reuse with replayed messages and
    key reinstallation [http://w1.fi/security/2017-1/]
    (CVE-2017-13082) (boo#1056061)

  - added support for FILS (IEEE 802.11ai) shared key
    authentication

  - added support for OWE (Opportunistic Wireless
    Encryption, RFC 8110; and transition mode defined by
    WFA)

  - added support for DPP (Wi-Fi Device Provisioning
    Protocol)

  - FT :

  - added local generation of PMK-R0/PMK-R1 for FT-PSK
    (ft_psk_generate_local=1)

  - replaced inter-AP protocol with a cleaner design that is
    more easily extensible; this breaks backward
    compatibility and requires all APs in the ESS to be
    updated at the same time to maintain FT functionality

  - added support for wildcard R0KH/R1KH

  - replaced r0_key_lifetime (minutes) parameter with
    ft_r0_key_lifetime (seconds)

  - fixed wpa_psk_file use for FT-PSK

  - fixed FT-SAE PMKID matching

  - added expiration to PMK-R0 and PMK-R1 cache

  - added IEEE VLAN support (including tagged VLANs)

  - added support for SHA384 based AKM

  - SAE

  - fixed some PMKSA caching cases with SAE

  - added support for configuring SAE password separately of
    the WPA2 PSK/passphrase

  - added option to require MFP for SAE associations
    (sae_require_pmf=1)

  - fixed PTK and EAPOL-Key integrity and key-wrap algorithm
    selection for SAE; note: this is not backwards
    compatible, i.e., both the AP and station side
    implementations will need to be update at the same time
    to maintain interoperability

  - added support for Password Identifier

  - hostapd_cli: added support for command history and
    completion

  - added support for requesting beacon report

  - large number of other fixes, cleanup, and extensions

  - added option to configure EAPOL-Key retry limits
    (wpa_group_update_count and wpa_pairwise_update_count)

  - removed all PeerKey functionality

  - fixed nl80211 AP mode configuration regression with
    Linux 4.15 and newer

  - added support for using wolfSSL cryptographic library

  - fixed some 20/40 MHz coexistence cases where the BSS
    could drop to 20 MHz even when 40 MHz would be allowed

  - Hotspot 2.0

  - added support for setting Venue URL ANQP-element
    (venue_url)

  - added support for advertising Hotspot 2.0 operator icons

  - added support for Roaming Consortium Selection element

  - added support for Terms and Conditions

  - added support for OSEN connection in a shared RSN BSS

  - added support for using OpenSSL 1.1.1

  - added EAP-pwd server support for salted passwords"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://w1.fi/security/2017-1/]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1056061"
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
    value:"https://w1.fi/security/2019-3/]"
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
    value:"Update the affected hostapd packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9499");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hostapd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:hostapd-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/02/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/18");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"hostapd-2.9-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"hostapd-debuginfo-2.9-lp151.4.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"hostapd-debugsource-2.9-lp151.4.3.1") ) flag++;

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
