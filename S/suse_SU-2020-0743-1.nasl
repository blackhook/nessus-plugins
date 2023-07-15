#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0743-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134852);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/13");

  script_cve_id("CVE-2018-10811", "CVE-2018-16151", "CVE-2018-16152", "CVE-2018-17540", "CVE-2018-5388", "CVE-2018-6459");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : strongswan (SUSE-SU-2020:0743-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for strongswan fixes the following issues :

Strongswan was updated to version 5.8.2 (jsc#SLE-11370).

Security issue fixed :

CVE-2018-6459: Fixed a DoS vulnerability in the parser for PKCS#1
RSASSA-PSS signatures that was caused by insufficient input validation
(bsc#1079548).

Full changelogs :

Version 5.8.2

  - Identity-based CA constraints, which enforce that the
    certificate chain of the remote peer contains a CA
    certificate with a specific identity, are supported via
    vici/swanctl.conf. This is similar to the existing CA
    constraints but doesn't require that the CA certificate
    is locally installed, for instance, intermediate CA
    certificates received from the peers. Wildcard identity
    matching (e.g. ..., OU=Research, CN=*) could also be
    used for the latter but requires trust in the
    intermediate CAs to only issue certificates with
    legitimate subject DNs (e.g. the 'Sales' CA must not
    issue certificates with OU=Research). With the new
    constraint that's not necessary as long as a path length
    basic constraint (--pathlen for pki --issue) prevents
    intermediate CAs from issuing further intermediate CAs.

  - Intermediate CA certificates may now be sent in
    hash-and-URL encoding by configuring a base URL for the
    parent CA (#3234, swanctl/rw-hash-and-url-multi-level).

  - Implemented NIST SP-800-90A Deterministic Random Bit
    Generator (DRBG) based on AES-CTR and SHA2-HMAC modes.
    Currently used by the gmp and ntru plugins.

  - Random nonces sent in an OCSP requests are now expected
    in the corresponding OCSP responses.

  - The kernel-netlink plugin now ignores deprecated IPv6
    addresses for MOBIKE. Whether temporary or permanent
    IPv6 addresses are included now depends on the
    charon.prefer_temporary_addrs setting (#3192).

  - Extended Sequence Numbers (ESN) are configured via
    PF_KEY if supported by the kernel.

  - The PF_KEY socket's receive buffer in the kernel-pfkey
    plugin is now cleared before sending requests, as many
    of the messages sent by the kernel are sent as
    broadcasts to all PF_KEY sockets. This is an issue if an
    external tool is used to manage SAs/policies unrelated
    to IPsec (#3225).

  - The vici plugin now uses unique section names for
    CHILD_SAs in child-updown events (7c74ce9190).

  - For individually deleted CHILD_SAs (in particular for
    IKEv1) the vici child-updown event now includes more
    information about the CHILD_SAs such as traffic
    statistics (#3198).

  - Custom loggers are correctly re-registered if log levels
    are changed via stroke loglevel (#3182).

  - Avoid lockups during startup on low entropy systems when
    using OpenSSL 1.1.1 (095a2c2eac).

  - Instead of failing later when setting a key, creating
    HMACs via openssl plugin now fails instantly if the
    underlying hash algorithm isn't supported (e.g. MD5 in
    FIPS-mode) so fallbacks to other plugins work properly
    (#3284).

  - Exponents of RSA keys read from TPM 2.0 via SAPI are
    correctly converted (8ee1242f1438).

  - Routing table IDs > 255 are supported for custom routes
    on Linux.

  - To avoid races, the check for hardware offloading
    support in the kernel-netlink plugin is performed during
    initialization of the plugin (a605452c03).

  - The D-Bus config file for charon-nm is now installed in
    $(datadir)/dbus-1/system.d instead of
    $(sysconfdir)/dbus-1/system.d, which is intended for
    sysadmin overrides. INVALID_MAJOR_VERSION notifies are
    now correctly sent in messages of the same exchange type
    and with the same message ID as the request.

  - IKEv2 SAs are now immediately destroyed when sending or
    receiving INVALID_SYNTAX notifies in authenticated
    messages.

  - For developers working from the repository the configure
    script now aborts if GNU gperf is not found.

Version 5.8.1

  - RDNs in DNs of X.509 certificates can now optionally be
    matched less strict. The global strongswan.conf option
    charon.rdn_matching takes two alternative values that
    cause the matching algorithm to either ignore the order
    of matched RDNs (reordered) or additionally (relaxed)
    accept DNs that contain more RDNs than configured
    (unmatched RDNs are treated like wildcard matches).

  - The updown plugin now passes the same interface to the
    script that is also used for the automatically installed
    routes, that is, the interface over which the peer is
    reached instead of the interface on which the local
    address is found (#3095).

  - TPM 2.0 contexts are now protected by a mutex to prevent
    issues if multiple IKE_SAs use the same private key
    concurrently (4b25885025).

  - Do a rekey check after the third QM message was received
    (#3060).

  - If available, explicit_bzero() is now used as memwipe()
    instead of our own implementation.

  - An .editorconfig file has been added, mainly so Github
    shows files with proper indentation (68346b6962).

  - The internal certificate of the load-tester plugin has
    been modified so it can again be used as end-entity cert
    with 5.6.3 and later (#3139).

  - The maximum data length of received COOKIE notifies (64
    bytes) is now enforced (#3160).

Version 5.8.0

  - The systemd service units have been renamed. The modern
    unit, which was called strongswan-swanctl, is now called
    strongswan (the previous name is configured as alias in
    the unit, for which a symlink is created when the unit
    is enabled). The legacy unit is now called
    strongswan-starter.

  - Support for XFRM interfaces (available since Linux 4.19)
    has been added, which are intended to replace VTI
    devices (they are similar but offer several advantages,
    for instance, they are not bound to an address or
    address family).

  - IPsec SAs and policies are associated with such
    interfaces via interface IDs that can be configured in
    swanctl.conf (dynamic IDs may optionally be allocated
    for each SA and even direction). It's possible to use
    separate interfaces for in- and outbound traffic (or
    only use an interface in one direction and regular
    policies in the other).

  - Interfaces may be created dynamically via updown/vici
    scripts, or statically before or after establishing the
    SAs. Routes must be added manually as needed (the daemon
    will not install any routes for outbound policies with
    an interface ID).

  - When moving XFRM interfaces to other network namespaces
    they retain access to the SAs and policies installed in
    the original namespace, which allows providing IPsec
    tunnels for processes in other network namespaces
    without giving them access to the IPsec keys or IKE
    credentials. More information can be found on the page
    about route-based VPNs.

  - Initiation of childless IKE_SAs is supported (RFC 6023).
    If enabled and supported by the responder, no CHILD_SA
    is established during IKE_AUTH. Instead, all CHILD_SAs
    are created with CREATE_CHILD_SA exchanges. This allows
    using a separate DH exchange even for the first
    CHILD_SA, which is otherwise created during IKE_AUTH
    with keys derived from the IKE_SA's key material.

  - The swanctl --initiate command may be used to initiate
    only the IKE_SA via --ike option if --child is omitted
    and the peer supports this extension.

  - The NetworkManager backend and plugin support IPv6.

  - The new wolfssl plugin is a wrapper around the wolfSSL
    crypto library. Thanks to Sean Parkinson of wolfSSL Inc.
    for the initial patch.

  - IKE SPIs may optionally be labeled via the
    charon.spi_mask|label options in strongswan.conf. This
    feature was extracted from charon-tkm, however, now
    applies the mask/label in network order.

  - The openssl plugin supports ChaCha20-Poly1305 when built
    with OpenSSL 1.1.0.

  - The PB-TNC finite state machine according to section 3.2
    of RFC 5793 was not correctly implemented when sending
    either a CRETRY or SRETRY batch. These batches can only
    be sent in the 'Decided' state and a CRETRY batch can
    immediately carry all messages usually transported by a
    CDATA batch. It is currently not possible to send a
    SRETRY batch since full-duplex mode for PT-TLS transport
    is not supported.

  - Instead of marking IPv6 virtual IPs as deprecated, the
    kernel-netlink plugin now uses address labels to avoid
    that such addresses are used for non-VPN traffic
    (00a953d090).

  - The agent plugin now creates sockets to the
    ssh/gpg-agent dynamically and does not keep them open,
    which otherwise might prevent the agent from getting
    terminated.

  - To avoid broadcast loops the forecast plugin now only
    reinjects packets that are marked or received from the
    configured interface.

  - UTF-8 encoded passwords are supported via EAP-MSCHAPv2,
    which internally uses an UTF-16LE encoding to calculate
    the NT hash (#3014).

  - Properly delete temporary drop policies (used when
    updating IP addresses of SAs) if manual priorities are
    used, which was broken since 5.6.2 (8e31d65730).

  - Avoid overwriting start_action when parsing the
    inactivity timeout in the vici plugin (#2954).

  - Fixed the automatic termination of reloaded vici
    connections with start_action=start, which was broken
    since 5.6.3 (71b22c250f).

  - The lookup for shared secrets for IKEv1 SAs via sql
    plugin should now work better (6ec9f68f32).

  - Fixed a race condition in the trap manager between
    installation and removal of a policy (69cbe2ca3f).

  - The IPsec stack detection and module loading in starter
    has been removed (it wasn't enforced anyway and loading
    modules doesn't seem necessary, also KLIPS hasn't been
    supported for a long time and PF_KEY will eventually be
    removed from the Linux kernel, ba817d2917).

  - Several IKEv2 protocol details are now handled more
    strictly: Unrequested virtual IPs are ignored, CFG_REPLY
    payloads are ignored if no CFG_REQUEST payloads were
    sent, a USE TRANSPORT_MODE notify received from the
    responder is checked against the local configuration.

  - The keys and certificates used by the scenarios in the
    testing environment are now generated dynamically.
    Running the testing/scripts/build-certs script after
    creating the base and root images uses the pki utility
    installed in the latter to create the keys and
    certificates for all the CAs and in some cases for
    individual scenarios. These credentials are stored in
    the source tree, not the image, so this has to be called
    only once even if the images are later rebuilt. The
    script automatically (re-)rebuilds the guest images as
    that generates fresh CRLs and signs the DNS zones. The
    only keys/certificates currently not generated are the
    very large ones used by the ikev2/rw-eap-tls-fragments
    scenario.

Version 5.7.2

  - For RSA with PSS padding, the TPM 2.0 specification
    mandates the maximum salt length (as defined by the
    length of the key and hash). However, if the TPM is
    FIPS-168-4 compliant, the salt length equals the hash
    length. This is assumed for FIPS-140-2 compliant TPMs,
    but if that's not the case, it might be necessary to
    manually enable charon.plugins.tpm.fips_186_4 if the TPM
    doesn't use the maximum salt length.

  - Directories for credentials loaded by swanctl are now
    accessed relative to the loaded swanctl.conf file, in
    particular, when loading it from a custom location via
    --file argument.

  - The base directory, which is used if no custom location
    for swanctl.conf is specified, is now also configurable
    at runtime via SWANCTL_DIR environment variable.

  - If RADIUS Accounting is enabled, the eap-radius plugin
    will add the session ID (Acct-Session-Id) to
    Access-Request messages, which e.g. simplifies
    associating database entries for IP leases and
    accounting with sessions (the session ID does not change
    when IKE_SAs are rekeyed, #2853).

  - All IP addresses assigned by a RADIUS server are
    included in Accounting-Stop messages even if the client
    did not claim them, allowing to release them early in
    case of connection errors (#2856).

  - Selectors installed on transport mode SAs by the
    kernel-netlink plugin are now updated if an IP address
    changes (e.g. via MOBIKE) and it was part of the
    selectors.

  - No deletes are sent anymore when a rekeyed CHILD_SA
    expires (#2815).

  - The bypass-lan plugin now tracks interfaces to handle
    subnets that move from one interface to another and
    properly update associated routes (#2820).

  - Only valid and expected inbound IKEv2 messages are used
    to update the timestamp of the last received message
    (previously, retransmits also triggered an update).

  - IKEv2 requests from responders are now ignored until the
    IKE_SA is fully established (e.g. if a DPD request from
    the peer arrives before the IKE_AUTH response does,
    46bea1add9). Delayed IKE_SA_INIT responses with COOKIE
    notifies we already recevied are ignored, they caused
    another reset of the IKE_SA previously (#2837).

  - Active and queued Quick Mode tasks are now adopted if
    the peer reauthenticates an IKEv1 SA while creating lots
    of CHILD_SAs.

  - Newer versions of the FreeBSD kernel add an
    SADB_X_EXT_SA2 extension to SADB_ACQUIRE messages, which
    allows the kernel-pfkey plugin to determine the reqid of
    the policy even if it wasn't installed by the daemon
    previously (e.g. when using FreeBSD's if_ipsec(4) VTIs,
    which install policies themselves, 872b9b3e8d).

  - Added support for RSA signatures with SHA-256 and
    SHA-512 to the agent plugin. For older versions of
    ssh/gpg-agent that only support SHA-1, IKEv2 signature
    authentication has to be disabled via
    charon.signature_authentication.

  - The sshkey and agent plugins support Ed25519/Ed448 SSH
    keys and signatures.

  - The openssl plugin supports X25519/X448 Diffie-Hellman
    and Ed25519/Ed448 keys and signatures when built against
    OpenSSL 1.1.1.

  - Support for Ed25519, ChaCha20/Poly1305, SHA-3 and
    AES-CCM were added to the botan plugin.

  - The mysql plugin now properly handles database
    connections with transactions under heavy load (#2779).

  - IP addresses in ha pools are now distributed evenly
    among all segments (#2828).

  - Private key implementations may optionally provide a
    list of supported signature schemes, which, as described
    above, is used by the tpm plugin because for each key on
    a TPM 2.0 the hash algorithm and for RSA also the
    padding scheme is predefined.

  - The testing environment is now based on Debian 9
    (stretch) by default. This required some changes, in
    particular, updating to FreeRADIUS 3.x (which forced us
    to abandon the TNC@FHH patches and scenarios,
    2fbe44bef3) and removing FIPS-enabled versions of
    OpenSSL (the FIPS module only supports OpenSSL 1.0.2).

  - Most test scenarios were migrated to swanctl.

Version 5.7.1

  - Fixes a vulnerability in the gmp plugin triggered by
    crafted certificates with RSA keys with very small
    moduli. When verifying signatures with such keys, the
    code patched with the fix for CVE-2018-16151/2 caused an
    integer underflow and subsequent heap buffer overflow
    that results in a crash of the daemon.

  - The vulnerability has been registered as CVE-2018-17540.

Version 5.7.0

  - Fixes a potential authorization bypass vulnerability in
    the gmp plugin that was caused by a too lenient
    verification of PKCS#1 v1.5 signatures. Several flaws
    could be exploited by a Bleichenbacher-style attack to
    forge signatures for low-exponent keys (i.e. with e=3).

  - CVE-2018-16151 has been assigned to the problem of
    accepting random bytes after the OID of the hash
    function in such signatures, and CVE-2018-16152 has been
    assigned to the issue of not verifying that the
    parameters in the ASN.1 algorithmIdentitifer structure
    is empty. Other flaws that don't lead to a vulnerability
    directly (e.g. not checking for at least 8 bytes of
    padding) have no separate CVE assigned.

  - Dots are not allowed anymore in section names in
    swanctl.conf and strongswan.conf. This mainly affects
    the configuration of file loggers. If the path for such
    a log file contains dots it now has to be configured in
    the new path setting within the arbitrarily renamed
    subsection in the filelog section.

  - Sections in swanctl.conf and strongswan.conf may now
    reference other sections. All settings and subsections
    from such a section are inherited. This allows to
    simplify configs as redundant information has only to be
    specified once and may then be included in other
    sections (see strongswan.conf for an example).

  - The originally selected IKE config (based on the IPs and
    IKE version) can now change if no matching algorithm
    proposal is found. This way the order of the configs
    doesn't matter that much anymore and it's easily
    possible to specify separate configs for clients that
    require weaker algorithms (instead of having to also add
    them in other configs that might be selected).

  - Support for Postquantum Preshared Keys for IKEv2
    (draft-ietf-ipsecme-qr-ikev2) has been added. For an
    example refer to the swanctl/rw-cert-ppk scenario (or
    with EAP, or PSK authentication).

  - The new botan plugin is a wrapper around the Botan C++
    crypto library. It requires a fairly recent build from
    Botan's master branch (or the upcoming 2.8.0 release).
    Thanks to Ren&Atilde;&#131;&Acirc;&copy; Korthaus and
    his team from Rohde & Schwarz Cybersecurity for the
    initial patch and to Jack Lloyd for quickly adding
    missing functions to Botan's FFI (C89) interface.

  - Implementation of RFC 8412 'Software Inventory Message
    and Attributes (SWIMA) for PA-TNC'.

  - SWIMA subscription option sets CLOSE_WRITE trigger on
    apt history.log file resulting in a ClientRetry PB-TNC
    batch to initialize a new measurement cycle. The new
    imv/imc-swima plugins replace the previous imv/imc-swid
    plugins, which were removed.

  - Added support for fuzzing the PA-TNC (RFC 5792) and
    PB-TNC (RFC 5793) NEA protocols on Google's OSS-Fuzz
    infrastructure.

  - Support for version 2 of Intel's TPM2-TSS TGC Software
    Stack. The presence of the in-kernel /dev/tpmrm0
    resource manager is automatically detected.

  - The pki tool accepts a xmppAddr otherName as a
    subjectAlternativeName using the syntax --san
    xmppaddr:<jid>.

  - swanctl.conf supports the configuration of marks the in-
    and/or outbound SA should apply to packets after
    processing on Linux. Configuring such a mark for
    outbound SAs requires at least a 4.14 kernel. The
    ability to set a mask and configuring a mark/mask for
    inbound SAs will be added with the upcoming 4.19 kernel.

  - New options in swanctl.conf allow configuring
    how/whether DF, ECN and DS fields in the IP headers are
    copied during IPsec processing. Controlling this is
    currently only possible on Linux.

  - The handling of sequence numbers in IKEv1 DPDs has been
    improved (#2714).

  - To avoid conflicts, the dhcp plugin now only uses the
    DHCP server port if explicitly configured.

Version 5.6.3

  - Fixed a DoS vulnerability in the IKEv2 key derivation if
    the openssl plugin is used in FIPS mode and HMAC-MD5 is
    negotiated as PRF. This vulnerability has been
    registered as CVE-2018-10811.

  - Fixed a vulnerability in the stroke plugin, which did
    not check the received length before reading a message
    from the socket. Unless a group is configured, root
    privileges are required to access that socket, so in the
    default configuration this shouldn't be an issue. This
    vulnerability has been registered as CVE-2018-5388.

  - CRLs that are not yet valid are now ignored to avoid
    problems in scenarios where expired certificates are
    removed from new CRLs and the clock on the host doing
    the revocation check is trailing behind that of the host
    issuing CRLs. Not doing this could result in accepting a
    revoked and expired certificate, if it's still valid
    according to the trailing clock but not contained
    anymore in not yet valid CRLs.

  - The issuer of fetched CRLs is now compared to the issuer
    of the checked certificate (#2608).

  - CRL validation results other than revocation (e.g. a
    skipped check because the CRL couldn't be fetched) are
    now stored also for intermediate CA certificates and not
    only for end-entity certificates, so a strict CRL policy
    can be enforced in such cases.

  - In compliance with RFC 4945, section 5.1.3.2,
    certificates used for IKE must now either not contain a
    keyUsage extension (like the ones generated by pki), or
    have at least one of the digitalSignature or
    nonRepudiation bits set.

  - New options for vici/swanctl allow forcing the local
    termination of an IKE_SA. This might be useful in
    situations where it's known the other end is not
    reachable anymore, or that it already removed the
    IKE_SA, so retransmitting a DELETE and waiting for a
    response would be pointless.

  - Waiting only a certain amount of time for a response
    (i.e. shorter than all retransmits would be) before
    destroying the IKE_SA is also possible by additionally
    specifying a timeout in the forced termination request.

  - When removing routes, the kernel-netlink plugin now
    checks if it tracks other routes for the same
    destination and replaces the installed route instead of
    just removing it. Same during installation, where
    existing routes previously weren't replaced. This should
    allow using traps with virtual IPs on Linux (#2162).

  - The dhcp plugin now only sends the client identifier
    DHCP option if the identity_lease setting is enabled
    (7b660944b6). It can also send identities of up to 255
    bytes length, instead of the previous 64 bytes
    (30e886fe3b, 0e5b94d038). If a server address is
    configured, DHCP requests are now sent from port 67
    instead of 68 to avoid ICMP port unreachables
    (becf027cd9).

  - The handling of faulty INVALID_KE_PAYLOAD notifies (e.g.
    one containing a DH group that wasn't proposed) during
    CREATE_CHILD_SA exchanges has been improved (#2536).

  - Roam events are now completely ignored for IKEv1 SAs
    (there is no MOBIKE to handle such changes properly).

  - ChaCha20/Poly1305 is now correctly proposed without key
    length (#2614). For compatibility with older releases
    the chacha20poly1305compat keyword may be included in
    proposals to also propose the algorithm with a key
    length (c58434aeff).

  - Configuration of hardware offload of IPsec SAs is now
    more flexible and allows a new setting (auto), which
    automatically uses it if the kernel and device both
    support it. If hw offload is set to yes and offloading
    is not supported, the CHILD_SA installation now fails.

  - The kernel-pfkey plugin optionally installs routes via
    internal interface (one with an IP in the local traffic
    selector). On FreeBSD, enabling this selects the correct
    source IP when sending packets from the gateway itself
    (e811659323).

  - SHA-2 based PRFs are supported in PKCS#8 files as
    generated by OpenSSL 1.1 (#2574).

  - The pki --verify tool may load CA certificates and CRLs
    from directories.

  - The IKE daemon now also switches to port 4500 if the
    remote port is not 500 (e.g. because the remote maps the
    response to a different port, as might happen on Azure),
    as long as the local port is 500 (85bfab621d).

  - Fixed an issue with DNS servers passed to NetworkManager
    in charon-nm (ee8c25516a).

  - Logged traffic selectors now always contain the protocol
    if either protocol or port are set (a36d8097ed).

  - Only the inbound SA/policy will be updated as reaction
    to IP address changes for rekeyed CHILD_SAs that are
    kept around.

  - The parser for strongswan.conf/swanctl.conf now accepts
    = characters in values without having to put the value
    in quotes (e.g. for Base64 encoded shared secrets).

    Notes for developers :

  - trap_manager_t: Trap policies are now unistalled by
    peer/child name and not the reqid.

  - No reqid is returned anymore when installing trap
    policies.

  - child_sa_t: A new state (CHILD_DELETED) is used for
    CHILD_SAs that have been deleted but not yet destroyed
    (after a rekeying CHILD_SAs are kept around for a while
    to process delayed packets). This way child_updown
    events are not triggered anymore for such SAs when an
    IKE_SA that has such CHILD_SAs assigned is deleted.

Version 5.6.2

  - Fixed a DoS vulnerability in the parser for PKCS#1
    RSASSA-PSS signatures that was caused by insufficient
    input validation. One of the configurable parameters in
    algorithm identifier structures for RSASSA-PSS
    signatures is the mask generation function (MGF). Only
    MGF1 is currently specified for this purpose. However,
    this in turn takes itself a parameter that specifies the
    underlying hash function. strongSwan's parser did not
    correctly handle the case of this parameter being
    absent, causing an undefined data read. This
    vulnerability has been registered as CVE-2018-6459.

  - When rekeying IKEv2 IKE_SAs the previously negotiated DH
    group will be reused, instead of using the first
    configured group, which avoids an additional exchange if
    the peer previously selected a different DH group via
    INVALID_KE_PAYLOAD notify. The same is also done when
    rekeying CHILD_SAs except for the first rekeying of the
    CHILD_SA that was created with the IKE_SA, where no DH
    group was negotiated yet. Also, the selected DH group is
    moved to the front in all sent proposals that contain it
    and all proposals that don't are moved to the back in
    order to convey the preference for this group to the
    peer.

  - Handling of MOBIKE task queuing has been improved. In
    particular, the response to an address update (with
    NAT-D payloads) is not ignored anymore if only an
    address list update or DPD is queued as that could
    prevent updating the UDP encapsulation in the kernel.

  - On Linux, roam events may optionally be triggered by
    changes to the routing rules, which can be useful if
    routing rules (instead of e.g. route metrics) are used
    to switch from one to another interface (i.e. from one
    to another routing table). Since routing rules are
    currently not evaluated when doing route lookups this is
    only useful if the kernel-based route lookup is used
    (4664992f7d).

  - The fallback drop policies installed to avoid traffic
    leaks when replacing addresses in installed policies are
    now replaced by temporary drop policies, which also
    prevent acquires because we currently delete and
    reinstall IPsec SAs to update their addresses
    (35ef1b032d).

  - Access X.509 certificates held in non-volatile storage
    of a TPM 2.0 referenced via the NV index. Adding the
    --keyid parameter to pki

    --print allows to print private keys or certificates
    stored in a smartcard or a TPM 2.0.

  - Fixed proposal selection if a peer incorrectly sends DH
    groups in the ESP proposal during IKE_AUTH and also if a
    DH group is configured in the local ESP proposal and
    charon.prefer configured_proposals is disabled
    (d058fd3c32).

  - The lookup for PSK secrets for IKEv1 has been improved
    for certain scenarios (see #2497 for details).

  - MSKs received via RADIUS are now padded to 64 bytes to
    avoid compatibility issues with EAP-MSCHAPv2 and PRFs
    that have a block size Version 5.6.1

  - Several algorithms were removed from the default ESP/AH
    and IKE proposals in compliance with RFC 8221 and RFC
    8247, respectively. Removed from the default ESP/AH
    proposal were the 3DES and Blowfish encryption
    algorithms and the HMAC-MD5 integrity algorithm. From
    the IKE default proposal the HMAC-MD5 integrity
    algorithm and the MODP-1024 Diffie-Hellman group were
    removed (the latter is significant for Windows clients
    in their default configuration). These algorithms may
    still be used in custom proposals.

  - Support for RSASSA-PSS signatures has been added. For
    compatibility with previous releases they are currently
    not used automatically, by default, to change that
    charon.rsa_pss may be enabled. To explicitly use or
    require such signatures during IKEv2 signature
    authentication (RFC 7427) ike:rsa/pss... authentication
    constraints may be used for specific connections
    (regardless of whether the strongswan.conf option above
    is enabled). Only the hash algorithm can be specified in
    such constraints, the MGF1 will be based on that hash
    and the salt length will equal the hash length (when
    verifying the salt length is not enforced). To enforce
    such signatures during PKI verification use rsa/pss...
    authentication constraints.

  - All pki commands that create certificates/CRLs can be
    made to sign with RSASSA-PSS instead of the classing
    PKCS#1 scheme with the --rsa-padding pss option. As with
    signatures during authentication, only the hash
    algorithm is configurable (via --digest option), the
    MGF1 will be based on that and the salt length will
    equal the hash length.

  - These signatures are supported by all RSA backends
    except pkcs11 (i.e. gmp, gcrypt, openssl). The gmp
    plugin requires the mgf1 plugin. Note that RSASSA-PSS
    algorithm identifiers and parameters in keys (public
    keys in certificates or private keys in PKCS#8 files)
    are currently not used as constraints.

  - The sec-updater tool checks for security updates in
    dpkg-based repositories (e.g. Debian/Ubuntu) and sets
    the security flags in the IMV policy database
    accordingly. Additionally for each new package version a
    SWID tag for the given OS and HW architecture is created
    and stored in the database.

  - Using the sec-updater.sh script template the lookup can
    be automated (e.g. via an hourly cron job).

  - When restarting an IKEv2 negotiation after receiving an
    INVALID_KE_PAYLOAD notify (or due to other reasons like
    too many retransmits) a new initiator SPI is allocated.
    This prevents issues caused by retransmits for
    IKE_SA_INIT messages.

  - Because the initiator SPI was previously reused when
    restarting the connection delayed responses for previous
    connection attempts were processed and might have caused
    fatal errors due to a failed DH negotiation or because
    of the internal retry counter in the ike-init task. For
    instance, if we proposed a DH group the responder
    rejected we might have later received delayed responses
    that either contained INVALID_KE_PAYLOAD notifies with
    the DH group we already switched to, or, if we
    retransmitted an IKE_SA_INIT with the requested group
    but then had to restart again, a KE payload with a group
    different from the one we proposed.

  - The introduction of file versions in the IMV database
    scheme broke file reference hash measurements. This has
    been fixed by creating generic product versions having
    an empty package name.

  - A new timeout option for the systime-fix plugin stops
    periodic system time checks after a while and enforces a
    certificate verification, closing or reauthenticating
    all SAs with invalid certificates.

  - The IKE event counters, previously only available via
    ipsec listcounters command, may now also be queried and
    reset via vici and the new swanctl --counters command.
    They are collected and provided by the optional counters
    plugin (enabled by default for backwards compatibility
    if the stroke plugin is built).

  - Class attributes received in RADIUS Access-Accept
    messages may optionally be added to RADIUS accounting
    messages (655924074b).

  - Basic support for systemd sockets has been added, which
    may be used for privilege separation (59db98fb94).

  - Inbound marks may optionally be installed in the SA
    again (was removed with 5.5.2) by enabling the
    mark_in_sa option in swanctl.conf.

  - The timeout of leases in pools configured via pool
    utility may be configured in other units than hours.
    INITIAL_CONTACT notifies are now only omitted if never
    is configured as uniqueness policy.

  - Outbound FWD policies for shunts are not installed
    anymore, by default (as is the case for other policies
    since 5.5.1).

  - Don't consider a DH group mismatch during CHILD_SA
    rekeying as failure as responder (e7276f78aa).

  - Handling of fragmented IPv4 and IPv6 packets in libipsec
    has been improved (e138003de9).

  - Trigger expire events for the correct IPsec SA in
    libipsec (6e861947a0).

  - A crash in CRL verification via openssl plugin using
    OpenSSL 1.1 has been fixed (78acaba6a1).

  - No hard-coded default proposals are passed from starter
    to the stroke plugin anymore (the IKE proposal used
    curve25519 since 5.5.2, which is an optional plugin).

  - A workaround for an issue with virtual IPs on macOS
    10.13 (High Sierra) has been added (039b85dd43).

  - Handling of IKE_SA rekey collisions in charon-tkm has
    been fixed.

  - Instead of failing or just silently doing nothing unit
    tests may now warn about certain conditions (e.g. if a
    test was not executed due to external dependencies).

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1079548"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-6459/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200743-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?219eb741"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-743=1

SUSE Linux Enterprise Module for Basesystem 15-SP1:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-SP1-2020-743=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16152");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-ipsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-ipsec-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-libs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-libs0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-nm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-nm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:strongswan-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/24");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-debugsource-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-hmac-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-ipsec-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-ipsec-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-libs0-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-libs0-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-mysql-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-mysql-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-nm-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-nm-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-sqlite-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"strongswan-sqlite-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-debugsource-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-hmac-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-ipsec-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-ipsec-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-libs0-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-libs0-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-mysql-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-mysql-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-nm-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-nm-debuginfo-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-sqlite-5.8.2-4.6.14")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"strongswan-sqlite-debuginfo-5.8.2-4.6.14")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "strongswan");
}
