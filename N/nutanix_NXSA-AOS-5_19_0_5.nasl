#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164556);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2017-12652",
    "CVE-2017-15715",
    "CVE-2017-18190",
    "CVE-2017-18551",
    "CVE-2018-1283",
    "CVE-2018-1303",
    "CVE-2018-10896",
    "CVE-2018-20836",
    "CVE-2018-20843",
    "CVE-2019-2974",
    "CVE-2019-5094",
    "CVE-2019-5188",
    "CVE-2019-5482",
    "CVE-2019-8675",
    "CVE-2019-8696",
    "CVE-2019-9454",
    "CVE-2019-9458",
    "CVE-2019-10098",
    "CVE-2019-11068",
    "CVE-2019-11719",
    "CVE-2019-11727",
    "CVE-2019-11756",
    "CVE-2019-12450",
    "CVE-2019-12614",
    "CVE-2019-12749",
    "CVE-2019-14822",
    "CVE-2019-14866",
    "CVE-2019-15217",
    "CVE-2019-15807",
    "CVE-2019-15903",
    "CVE-2019-15917",
    "CVE-2019-16231",
    "CVE-2019-16233",
    "CVE-2019-16935",
    "CVE-2019-16994",
    "CVE-2019-17006",
    "CVE-2019-17023",
    "CVE-2019-17053",
    "CVE-2019-17055",
    "CVE-2019-17498",
    "CVE-2019-18197",
    "CVE-2019-18808",
    "CVE-2019-19046",
    "CVE-2019-19055",
    "CVE-2019-19058",
    "CVE-2019-19059",
    "CVE-2019-19062",
    "CVE-2019-19063",
    "CVE-2019-19126",
    "CVE-2019-19332",
    "CVE-2019-19447",
    "CVE-2019-19523",
    "CVE-2019-19524",
    "CVE-2019-19530",
    "CVE-2019-19534",
    "CVE-2019-19537",
    "CVE-2019-19767",
    "CVE-2019-19807",
    "CVE-2019-19956",
    "CVE-2019-20054",
    "CVE-2019-20095",
    "CVE-2019-20386",
    "CVE-2019-20388",
    "CVE-2019-20636",
    "CVE-2019-20811",
    "CVE-2019-20907",
    "CVE-2019-1010305",
    "CVE-2020-1749",
    "CVE-2020-1927",
    "CVE-2020-1934",
    "CVE-2020-2574",
    "CVE-2020-2732",
    "CVE-2020-2752",
    "CVE-2020-2780",
    "CVE-2020-2812",
    "CVE-2020-6829",
    "CVE-2020-7595",
    "CVE-2020-8177",
    "CVE-2020-8492",
    "CVE-2020-8622",
    "CVE-2020-8623",
    "CVE-2020-8624",
    "CVE-2020-8631",
    "CVE-2020-8632",
    "CVE-2020-8647",
    "CVE-2020-8649",
    "CVE-2020-9383",
    "CVE-2020-10690",
    "CVE-2020-10732",
    "CVE-2020-10742",
    "CVE-2020-10751",
    "CVE-2020-10942",
    "CVE-2020-11565",
    "CVE-2020-12243",
    "CVE-2020-12400",
    "CVE-2020-12401",
    "CVE-2020-12402",
    "CVE-2020-12403",
    "CVE-2020-12770",
    "CVE-2020-12826",
    "CVE-2020-13943",
    "CVE-2020-14305",
    "CVE-2020-14331",
    "CVE-2020-14422",
    "CVE-2020-15999",
    "CVE-2020-17527"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2020-0124");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.19.0.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.19.0.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.19.0.5 advisory.

  - libpng before 1.6.32 does not properly check the length of chunks against the user limit. (CVE-2017-12652)

  - In Apache httpd 2.4.0 to 2.4.29, the expression specified in <FilesMatch> could match '$' to a newline
    character in a malicious filename, rather than matching only the end of the filename. This could be
    exploited in environments where uploads of some files are are externally blocked, but only by matching the
    trailing portion of the filename. (CVE-2017-15715)

  - A localhost.localdomain whitelist entry in valid_host() in scheduler/client.c in CUPS before 2.2.2 allows
    remote attackers to execute arbitrary IPP commands by sending POST requests to the CUPS daemon in
    conjunction with DNS rebinding. The localhost.localdomain name is often resolved via a DNS server (neither
    the OS nor the web browser is responsible for ensuring that localhost.localdomain is 127.0.0.1).
    (CVE-2017-18190)

  - An issue was discovered in drivers/i2c/i2c-core-smbus.c in the Linux kernel before 4.14.15. There is an
    out of bounds write in the function i2c_smbus_xfer_emulated. (CVE-2017-18551)

  - The default cloud-init configuration, in cloud-init 0.6.2 and newer, included ssh_deletekeys: 0,
    disabling cloud-init's deletion of ssh host keys. In some environments, this could lead to instances
    created by cloning a golden master or template system, sharing ssh host keys, and being able to
    impersonate one another or conduct man-in-the-middle attacks. (CVE-2018-10896)

  - In Apache httpd 2.4.0 to 2.4.29, when mod_session is configured to forward its session data to CGI
    applications (SessionEnv on, not the default), a remote user may influence their content by using a
    Session header. This comes from the HTTP_SESSION variable name used by mod_session to forward its data
    to CGIs, since the prefix HTTP_ is also used by the Apache HTTP Server to pass HTTP header fields, per
    CGI specifications. (CVE-2018-1283)

  - A specially crafted HTTP request header could have crashed the Apache HTTP Server prior to version 2.4.30
    due to an out of bound read while preparing data to be cached in shared memory. It could be used as a
    Denial of Service attack against users of mod_cache_socache. The vulnerability is considered as low risk
    since mod_cache_socache is not widely used, mod_cache_disk is not concerned by this vulnerability.
    (CVE-2018-1303)

  - An issue was discovered in the Linux kernel before 4.20. There is a race condition in smp_task_timedout()
    and smp_task_done() in drivers/scsi/libsas/sas_expander.c, leading to a use-after-free. (CVE-2018-20836)

  - In libexpat in Expat before 2.2.7, XML input including XML names that contain a large number of colons
    could make the XML parser consume a high amount of RAM and CPU resources while processing (enough to be
    usable for denial-of-service attacks). (CVE-2018-20843)

  - In Apache HTTP server 2.4.0 to 2.4.39, Redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an unexpected URL within the
    request URL. (CVE-2019-10098)

  - libmspack 0.9.1alpha is affected by: Buffer Overflow. The impact is: Information Disclosure. The component
    is: function chmd_read_headers() in libmspack(file libmspack/mspack/chmd.c). The attack vector is: the
    victim must open a specially crafted chm file. The fixed version is: after commit
    2f084136cfe0d05e5bf5703f3e83c6d955234b4d. (CVE-2019-1010305)

  - libxslt through 1.1.33 allows bypass of a protection mechanism because callers of xsltCheckRead and
    xsltCheckWrite permit access even upon receiving a -1 error code. xsltCheckRead can return -1 for a
    crafted URL that is not actually invalid and is subsequently loaded. (CVE-2019-11068)

  - When importing a curve25519 private key in PKCS#8format with leading 0x00 bytes, it is possible to trigger
    an out-of-bounds read in the Network Security Services (NSS) library. This could lead to information
    disclosure. This vulnerability affects Firefox ESR < 60.8, Firefox < 68, and Thunderbird < 60.8.
    (CVE-2019-11719)

  - A vulnerability exists where it possible to force Network Security Services (NSS) to sign
    CertificateVerify with PKCS#1 v1.5 signatures when those are the only ones advertised by server in
    CertificateRequest in TLS 1.3. PKCS#1 v1.5 signatures should not be used for TLS 1.3 messages. This
    vulnerability affects Firefox < 68. (CVE-2019-11727)

  - Improper refcounting of soft token session objects could cause a use-after-free and crash (likely limited
    to a denial of service). This vulnerability affects Firefox < 71. (CVE-2019-11756)

  - file_copy_fallback in gio/gfile.c in GNOME GLib 2.15.0 through 2.61.1 does not properly restrict file
    permissions while a copy operation is in progress. Instead, default permissions are used. (CVE-2019-12450)

  - An issue was discovered in dlpar_parse_cc_property in arch/powerpc/platforms/pseries/dlpar.c in the Linux
    kernel through 5.1.6. There is an unchecked kstrdup of prop->name, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system crash). (CVE-2019-12614)

  - dbus before 1.10.28, 1.12.x before 1.12.16, and 1.13.x before 1.13.12, as used in DBusServer in Canonical
    Upstart in Ubuntu 14.04 (and in some, less common, uses of dbus-daemon), allows cookie spoofing because of
    symlink mishandling in the reference implementation of DBUS_COOKIE_SHA1 in the libdbus library. (This only
    affects the DBUS_COOKIE_SHA1 authentication mechanism.) A malicious client with write access to its own
    home directory could manipulate a ~/.dbus-keyrings symlink to cause a DBusServer with a different uid to
    read and write in unintended locations. In the worst case, this could result in the DBusServer reusing a
    cookie that is known to the malicious client, and treating that cookie as evidence that a subsequent
    client connection came from an attacker-chosen uid, allowing authentication bypass. (CVE-2019-12749)

  - A flaw was discovered in ibus in versions before 1.5.22 that allows any unprivileged user to monitor and
    send method calls to the ibus bus of another user due to a misconfiguration in the DBus server setup. A
    local attacker may use this flaw to intercept all keystrokes of a victim user who is using the graphical
    interface, change the input method engine, or modify other input related configurations of the victim
    user. (CVE-2019-14822)

  - In all versions of cpio before 2.13 does not properly validate input files when generating TAR archives.
    When cpio is used to create TAR archives from paths an attacker can write to, the resulting archive may
    contain files with permissions the attacker did not have or in paths he did not have access to. Extracting
    those archives from a high-privilege user without carefully reviewing them may lead to the compromise of
    the system. (CVE-2019-14866)

  - An issue was discovered in the Linux kernel before 5.2.3. There is a NULL pointer dereference caused by a
    malicious USB device in the drivers/media/usb/zr364xx/zr364xx.c driver. (CVE-2019-15217)

  - In the Linux kernel before 5.1.13, there is a memory leak in drivers/scsi/libsas/sas_expander.c when SAS
    expander discovery fails. This will cause a BUG and denial of service. (CVE-2019-15807)

  - In libexpat before 2.2.8, crafted XML input could fool the parser into changing from DTD parsing to
    document parsing too early; a consecutive call to XML_GetCurrentLineNumber (or XML_GetCurrentColumnNumber)
    then resulted in a heap-based buffer over-read. (CVE-2019-15903)

  - An issue was discovered in the Linux kernel before 5.0.5. There is a use-after-free issue when
    hci_uart_register_dev() fails in hci_uart_set_proto() in drivers/bluetooth/hci_ldisc.c. (CVE-2019-15917)

  - drivers/net/fjes/fjes_main.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16231)

  - drivers/scsi/qla2xxx/qla_os.c in the Linux kernel 5.2.14 does not check the alloc_workqueue return value,
    leading to a NULL pointer dereference. (CVE-2019-16233)

  - The documentation XML-RPC server in Python through 2.7.16, 3.x through 3.6.9, and 3.7.x through 3.7.4 has
    XSS via the server_title field. This occurs in Lib/DocXMLRPCServer.py in Python 2.x, and in
    Lib/xmlrpc/server.py in Python 3.x. If set_server_title is called with untrusted input, arbitrary
    JavaScript can be delivered to clients that visit the http URL for this server. (CVE-2019-16935)

  - In the Linux kernel before 5.0, a memory leak exists in sit_init_net() in net/ipv6/sit.c when
    register_netdev() fails to register sitn->fb_tunnel_dev, which may cause denial of service, aka
    CID-07f12b26e21a. (CVE-2019-16994)

  - In Network Security Services (NSS) before 3.46, several cryptographic primitives had missing length
    checks. In cases where the application calling the library did not perform a sanity check on the inputs it
    could result in a crash due to a buffer overflow. (CVE-2019-17006)

  - After a HelloRetryRequest has been sent, the client may negotiate a lower protocol that TLS 1.3, resulting
    in an invalid state transition in the TLS State Machine. If the client gets into this state, incoming
    Application Data records will be ignored. This vulnerability affects Firefox < 72. (CVE-2019-17023)

  - ieee802154_create in net/ieee802154/socket.c in the AF_IEEE802154 network module in the Linux kernel
    through 5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket,
    aka CID-e69dbd4619e7. (CVE-2019-17053)

  - base_sock_create in drivers/isdn/mISDN/socket.c in the AF_ISDN network module in the Linux kernel through
    5.3.2 does not enforce CAP_NET_RAW, which means that unprivileged users can create a raw socket, aka
    CID-b91ee4aa2a21. (CVE-2019-17055)

  - In libssh2 v1.9.0 and earlier versions, the SSH_MSG_DISCONNECT logic in packet.c has an integer overflow
    in a bounds check, enabling an attacker to specify an arbitrary (out-of-bounds) offset for a subsequent
    memory read. A crafted SSH server may be able to disclose sensitive information or cause a denial of
    service condition on the client system when a user connects to the server. (CVE-2019-17498)

  - In xsltCopyText in transform.c in libxslt 1.1.33, a pointer variable isn't reset under certain
    circumstances. If the relevant memory area happened to be freed and reused in a certain way, a bounds
    check could fail and memory outside a buffer could be written to, or uninitialized data could be
    disclosed. (CVE-2019-18197)

  - A memory leak in the ccp_run_sha_cmd() function in drivers/crypto/ccp/ccp-ops.c in the Linux kernel
    through 5.3.9 allows attackers to cause a denial of service (memory consumption), aka CID-128c66429247.
    (CVE-2019-18808)

  - ** DISPUTED ** A memory leak in the __ipmi_bmc_register() function in drivers/char/ipmi/ipmi_msghandler.c
    in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by
    triggering ida_simple_get() failure, aka CID-4aa7afb0ee20. NOTE: third parties dispute the relevance of
    this because an attacker cannot realistically control this failure at probe time. (CVE-2019-19046)

  - ** DISPUTED ** A memory leak in the nl80211_get_ftm_responder_stats() function in net/wireless/nl80211.c
    in the Linux kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by
    triggering nl80211hdr_put() failures, aka CID-1399c59fa929. NOTE: third parties dispute the relevance of
    this because it occurs on a code path where a successful allocation has already occurred. (CVE-2019-19055)

  - A memory leak in the alloc_sgtable() function in drivers/net/wireless/intel/iwlwifi/fw/dbg.c in the Linux
    kernel through 5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    alloc_page() failures, aka CID-b4b814fec1a5. (CVE-2019-19058)

  - Multiple memory leaks in the iwl_pcie_ctxt_info_gen3_init() function in
    drivers/net/wireless/intel/iwlwifi/pcie/ctxt-info-gen3.c in the Linux kernel through 5.3.11 allow
    attackers to cause a denial of service (memory consumption) by triggering iwl_pcie_init_fw_sec() or
    dma_alloc_coherent() failures, aka CID-0f4f199443fa. (CVE-2019-19059)

  - A memory leak in the crypto_report() function in crypto/crypto_user_base.c in the Linux kernel through
    5.3.11 allows attackers to cause a denial of service (memory consumption) by triggering
    crypto_report_alg() failures, aka CID-ffdde5932042. (CVE-2019-19062)

  - Two memory leaks in the rtl_usb_probe() function in drivers/net/wireless/realtek/rtlwifi/usb.c in the
    Linux kernel through 5.3.11 allow attackers to cause a denial of service (memory consumption), aka
    CID-3f9361695113. (CVE-2019-19063)

  - On the x86-64 architecture, the GNU C Library (aka glibc) before 2.31 fails to ignore the
    LD_PREFER_MAP_32BIT_EXEC environment variable during program execution after a security transition,
    allowing local attackers to restrict the possible mapping addresses for loaded libraries and thus bypass
    ASLR for a setuid program. (CVE-2019-19126)

  - An out-of-bounds memory write issue was found in the Linux Kernel, version 3.13 through 5.4, in the way
    the Linux kernel's KVM hypervisor handled the 'KVM_GET_EMULATED_CPUID' ioctl(2) request to get CPUID
    features emulated by the KVM hypervisor. A user or process able to access the '/dev/kvm' device could use
    this flaw to crash the system, resulting in a denial of service. (CVE-2019-19332)

  - In the Linux kernel 5.0.21, mounting a crafted ext4 filesystem image, performing some operations, and
    unmounting can lead to a use-after-free in ext4_put_super in fs/ext4/super.c, related to dump_orphan_list
    in fs/ext4/super.c. (CVE-2019-19447)

  - In the Linux kernel before 5.3.7, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/misc/adutux.c driver, aka CID-44efc269db79. (CVE-2019-19523)

  - In the Linux kernel before 5.3.12, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/input/ff-memless.c driver, aka CID-fa3a5a1880c9. (CVE-2019-19524)

  - In the Linux kernel before 5.2.10, there is a use-after-free bug that can be caused by a malicious USB
    device in the drivers/usb/class/cdc-acm.c driver, aka CID-c52873e5a1ef. (CVE-2019-19530)

  - In the Linux kernel before 5.3.11, there is an info-leak bug that can be caused by a malicious USB device
    in the drivers/net/can/usb/peak_usb/pcan_usb_core.c driver, aka CID-f7a1337f0d29. (CVE-2019-19534)

  - In the Linux kernel before 5.2.10, there is a race condition bug that can be caused by a malicious USB
    device in the USB character device driver layer, aka CID-303911cfc5b9. This affects
    drivers/usb/core/file.c. (CVE-2019-19537)

  - The Linux kernel before 5.4.2 mishandles ext4_expand_extra_isize, as demonstrated by use-after-free errors
    in __ext4_expand_extra_isize and ext4_xattr_set_entry, related to fs/ext4/inode.c and fs/ext4/super.c, aka
    CID-4ea99936a163. (CVE-2019-19767)

  - In the Linux kernel before 5.3.11, sound/core/timer.c has a use-after-free caused by erroneous code
    refactoring, aka CID-e7af6307a8a5. This is related to snd_timer_open and snd_timer_close_locked. The
    timeri variable was originally intended to be for a newly created timer instance, but was used for a
    different purpose after refactoring. (CVE-2019-19807)

  - xmlParseBalancedChunkMemoryRecover in parser.c in libxml2 before 2.9.10 has a memory leak related to
    newDoc->oldNs. (CVE-2019-19956)

  - In the Linux kernel before 5.0.6, there is a NULL pointer dereference in drop_sysctl_table() in
    fs/proc/proc_sysctl.c, related to put_links, aka CID-23da9588037e. (CVE-2019-20054)

  - mwifiex_tm_cmd in drivers/net/wireless/marvell/mwifiex/cfg80211.c in the Linux kernel before 5.1.6 has
    some error-handling cases that did not free allocated hostcmd memory, aka CID-003b686ace82. This will
    cause a memory leak and denial of service. (CVE-2019-20095)

  - An issue was discovered in button_open in login/logind-button.c in systemd before 243. When executing the
    udevadm trigger command, a memory leak may occur. (CVE-2019-20386)

  - xmlSchemaPreRun in xmlschemas.c in libxml2 2.9.10 allows an xmlSchemaValidateStream memory leak.
    (CVE-2019-20388)

  - In the Linux kernel before 5.4.12, drivers/input/input.c has out-of-bounds writes via a crafted keycode
    table, as demonstrated by input_set_keycode, aka CID-cb222aed03d7. (CVE-2019-20636)

  - An issue was discovered in the Linux kernel before 5.0.6. In rx_queue_add_kobject() and
    netdev_queue_add_kobject() in net/core/net-sysfs.c, a reference count is mishandled, aka CID-a3e23f719f5c.
    (CVE-2019-20811)

  - In Lib/tarfile.py in Python through 3.8.3, an attacker is able to craft a TAR archive leading to an
    infinite loop when opened by tarfile.open, because _proc_pax lacks header validation. (CVE-2019-20907)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported
    versions that are affected are 5.6.45 and prior, 5.7.27 and prior and 8.0.17 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2974)

  - An exploitable code execution vulnerability exists in the quota file functionality of E2fsprogs 1.45.3. A
    specially crafted ext4 partition can cause an out-of-bounds write on the heap, resulting in code
    execution. An attacker can corrupt a partition to trigger this vulnerability. (CVE-2019-5094)

  - A code execution vulnerability exists in the directory rehashing functionality of E2fsprogs e2fsck 1.45.4.
    A specially crafted ext4 directory can cause an out-of-bounds write on the stack, resulting in code
    execution. An attacker can corrupt a partition to trigger this vulnerability. (CVE-2019-5188)

  - Heap buffer overflow in the TFTP protocol handler in cURL 7.19.4 to 7.65.3. (CVE-2019-5482)

  - A buffer overflow issue was addressed with improved memory handling. This issue is fixed in macOS Mojave
    10.14.6, Security Update 2019-004 High Sierra, Security Update 2019-004 Sierra. An attacker in a
    privileged network position may be able to execute arbitrary code. (CVE-2019-8675, CVE-2019-8696)

  - In the Android kernel in i2c driver there is a possible out of bounds write due to memory corruption. This
    could lead to local escalation of privilege with System execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9454)

  - In the Android kernel in the video driver there is a use after free due to a race condition. This could
    lead to local escalation of privilege with no additional execution privileges needed. User interaction is
    not needed for exploitation. (CVE-2019-9458)

  - There is a use-after-free in kernel versions before 5.5 due to a race condition between the release of
    ptp_clock and cdev while resource deallocation. When a (high privileged) process allocates a ptp device
    file (like /dev/ptpX) and voluntarily goes to sleep. During this time if the underlying device is removed,
    it can cause an exploitable condition as the process wakes up to terminate and clean all attached files.
    The system crashes due to the cdev structure being invalid (as already freed) which is pointed to by the
    inode. (CVE-2020-10690)

  - A flaw was found in the Linux kernel's implementation of Userspace core dumps. This flaw allows an
    attacker with a local account to crash a trivial program and exfiltrate private kernel data.
    (CVE-2020-10732)

  - A flaw was found in the Linux kernel. An index buffer overflow during Direct IO write leading to the NFS
    client to crash. In some cases, a reach out of the index after one memory allocation by kmalloc will cause
    a kernel panic. The highest threat from this vulnerability is to data confidentiality and system
    availability. (CVE-2020-10742)

  - A flaw was found in the Linux kernels SELinux LSM hook implementation before version 5.7, where it
    incorrectly assumed that an skb would only contain a single netlink message. The hook would incorrectly
    only validate the first netlink message in the skb and allow or deny the rest of the messages within the
    skb with the granted permission without further processing. (CVE-2020-10751)

  - In the Linux kernel before 5.5.8, get_raw_socket in drivers/vhost/net.c lacks validation of an sk_family
    field, which might allow attackers to trigger kernel stack corruption via crafted system calls.
    (CVE-2020-10942)

  - ** DISPUTED ** An issue was discovered in the Linux kernel through 5.6.2. mpol_parse_str in mm/mempolicy.c
    has a stack-based out-of-bounds write because an empty nodelist is mishandled during mount option parsing,
    aka CID-aa9f7d5172fa. NOTE: Someone in the security community disagrees that this is a vulnerability
    because the issue is a bug in parsing mount options which can only be specified by a privileged user, so
    triggering the bug does not grant any powers not already held.. (CVE-2020-11565)

  - In filter.c in slapd in OpenLDAP before 2.4.50, LDAP search filters with nested boolean expressions can
    result in denial of service (daemon crash). (CVE-2020-12243)

  - When converting coordinates from projective to affine, the modular inversion was not performed in constant
    time, resulting in a possible timing-based side channel attack. This vulnerability affects Firefox < 80
    and Firefox for Android < 80. (CVE-2020-12400)

  - During ECDSA signature generation, padding applied in the nonce designed to ensure constant-time scalar
    multiplication was removed, resulting in variable-time execution dependent on secret data. This
    vulnerability affects Firefox < 80 and Firefox for Android < 80. (CVE-2020-12401)

  - During RSA key generation, bignum implementations used a variation of the Binary Extended Euclidean
    Algorithm which entailed significantly input-dependent flow. This allowed an attacker able to perform
    electromagnetic-based side channel attacks to record traces leading to the recovery of the secret primes.
    *Note:* An unmodified Firefox browser does not generate RSA keys in normal operation and is not affected,
    but products built on top of it might. This vulnerability affects Firefox < 78. (CVE-2020-12402)

  - A flaw was found in the way CHACHA20-POLY1305 was implemented in NSS in versions before 3.55. When using
    multi-part Chacha20, it could cause out-of-bounds reads. This issue was fixed by explicitly disabling
    multi-part ChaCha20 (which was not functioning correctly) and strictly enforcing tag length. The highest
    threat from this vulnerability is to confidentiality and system availability. (CVE-2020-12403)

  - An issue was discovered in the Linux kernel through 5.6.11. sg_write lacks an sg_remove_request call in a
    certain failure case, aka CID-83c6f2390040. (CVE-2020-12770)

  - A signal access-control issue was discovered in the Linux kernel before 5.6.5, aka CID-7395ea4e65c2.
    Because exec_id in include/linux/sched.h is only 32 bits, an integer overflow can interfere with a
    do_notify_parent protection mechanism. A child process can send an arbitrary signal to a parent process in
    a different security domain. Exploitation limitations include the amount of elapsed time before an integer
    overflow occurs, and the lack of scenarios where signals to a parent process present a substantial
    operational threat. (CVE-2020-12826)

  - If an HTTP/2 client connecting to Apache Tomcat 10.0.0-M1 to 10.0.0-M7, 9.0.0.M1 to 9.0.37 or 8.5.0 to
    8.5.57 exceeded the agreed maximum number of concurrent streams for a connection (in violation of the
    HTTP/2 protocol), it was possible that a subsequent request made on that connection could contain HTTP
    headers - including HTTP/2 pseudo headers - from a previous request rather than the intended headers. This
    could lead to users seeing responses for unexpected resources. (CVE-2020-13943)

  - An out-of-bounds memory write flaw was found in how the Linux kernel's Voice Over IP H.323 connection
    tracking functionality handled connections on ipv6 port 1720. This flaw allows an unauthenticated remote
    user to crash the system, causing a denial of service. The highest threat from this vulnerability is to
    confidentiality, integrity, as well as system availability. (CVE-2020-14305)

  - A flaw was found in the Linux kernel's implementation of the invert video code on VGA consoles when a
    local attacker attempts to resize the console, calling an ioctl VT_RESIZE, which causes an out-of-bounds
    write to occur. This flaw allows a local user with access to the VGA console to crash the system,
    potentially escalating their privileges on the system. The highest threat from this vulnerability is to
    data confidentiality and integrity as well as system availability. (CVE-2020-14331)

  - Lib/ipaddress.py in Python through 3.8.3 improperly computes hash values in the IPv4Interface and
    IPv6Interface classes, which might allow a remote attacker to cause a denial of service if an application
    is affected by the performance of a dictionary containing IPv4Interface or IPv6Interface objects, and this
    attacker can cause many dictionary entries to be created. This is fixed in: v3.5.10, v3.5.10rc1; v3.6.12;
    v3.7.9; v3.8.4, v3.8.4rc1, v3.8.5, v3.8.6, v3.8.6rc1; v3.9.0, v3.9.0b4, v3.9.0b5, v3.9.0rc1, v3.9.0rc2.
    (CVE-2020-14422)

  - Heap buffer overflow in Freetype in Google Chrome prior to 86.0.4240.111 allowed a remote attacker to
    potentially exploit heap corruption via a crafted HTML page. (CVE-2020-15999)

  - A flaw was found in the Linux kernel's implementation of some networking protocols in IPsec, such as VXLAN
    and GENEVE tunnels over IPv6. When an encrypted tunnel is created between two hosts, the kernel isn't
    correctly routing tunneled data over the encrypted link; rather sending the data unencrypted. This would
    allow anyone in between the two endpoints to read the traffic unencrypted. The main threat from this
    vulnerability is to data confidentiality. (CVE-2020-1749)

  - While investigating bug 64830 it was discovered that Apache Tomcat 10.0.0-M1 to 10.0.0-M9, 9.0.0-M1 to
    9.0.39 and 8.5.0 to 8.5.59 could re-use an HTTP request header value from the previous stream received on
    an HTTP/2 connection for the request associated with the subsequent stream. While this would most likely
    lead to an error and the closure of the HTTP/2 connection, it is possible that information could leak
    between requests. (CVE-2020-17527)

  - In Apache HTTP Server 2.4.0 to 2.4.41, redirects configured with mod_rewrite that were intended to be
    self-referential might be fooled by encoded newlines and redirect instead to an an unexpected URL within
    the request URL. (CVE-2020-1927)

  - In Apache HTTP Server 2.4.0 to 2.4.41, mod_proxy_ftp may use uninitialized memory when proxying to a
    malicious FTP server. (CVE-2020-1934)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.46 and prior, 5.7.28 and prior and 8.0.18 and prior. Difficult to exploit vulnerability
    allows unauthenticated attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. (CVE-2020-2574)

  - A flaw was discovered in the way that the KVM hypervisor handled instruction emulation for an L2 guest
    when nested virtualisation is enabled. Under some circumstances, an L2 guest may trick the L0 guest into
    accessing sensitive L1 resources that should be inaccessible to the L2 guest. (CVE-2020-2732)

  - Vulnerability in the MySQL Client product of Oracle MySQL (component: C API). Supported versions that are
    affected are 5.6.47 and prior, 5.7.27 and prior and 8.0.17 and prior. Difficult to exploit vulnerability
    allows low privileged attacker with network access via multiple protocols to compromise MySQL Client.
    Successful attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Client. (CVE-2020-2752)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: DML). Supported versions
    that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2780)

  - Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Stored Procedure). Supported
    versions that are affected are 5.6.47 and prior, 5.7.29 and prior and 8.0.19 and prior. Easily exploitable
    vulnerability allows high privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2020-2812)

  - When performing EC scalar point multiplication, the wNAF point multiplication algorithm was used; which
    leaked partial information about the nonce used during signature generation. Given an electro-magnetic
    trace of a few signature generations, the private key could have been computed. This vulnerability affects
    Firefox < 80 and Firefox for Android < 80. (CVE-2020-6829)

  - xmlStringLenDecodeEntities in parser.c in libxml2 2.9.10 has an infinite loop in a certain end-of-file
    situation. (CVE-2020-7595)

  - curl 7.20.0 through 7.70.0 is vulnerable to improper restriction of names for files and other resources
    that can lead too overwriting a local file when the -J flag is used. (CVE-2020-8177)

  - Python 2.7 through 2.7.17, 3.5 through 3.5.9, 3.6 through 3.6.10, 3.7 through 3.7.6, and 3.8 through 3.8.1
    allows an HTTP server to conduct Regular Expression Denial of Service (ReDoS) attacks against a client
    because of urllib.request.AbstractBasicAuthHandler catastrophic backtracking. (CVE-2020-8492)

  - In BIND 9.0.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.9.3-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker on the network path for a TSIG-signed request, or operating
    the server receiving the TSIG-signed request, could send a truncated response to that request, triggering
    an assertion failure, causing the server to exit. Alternately, an off-path attacker would have to
    correctly guess when a TSIG-signed request was sent, along with other characteristics of the packet and
    message, and spoof a truncated response to trigger an assertion failure, causing the server to exit.
    (CVE-2020-8622)

  - In BIND 9.10.0 -> 9.11.21, 9.12.0 -> 9.16.5, 9.17.0 -> 9.17.3, also affects 9.10.5-S1 -> 9.11.21-S1 of the
    BIND 9 Supported Preview Edition, An attacker that can reach a vulnerable system with a specially crafted
    query packet can trigger a crash. To be vulnerable, the system must: * be running BIND that was built with
    --enable-native-pkcs11 * be signing one or more zones with an RSA key * be able to receive queries from
    a possible attacker (CVE-2020-8623)

  - In BIND 9.9.12 -> 9.9.13, 9.10.7 -> 9.10.8, 9.11.3 -> 9.11.21, 9.12.1 -> 9.16.5, 9.17.0 -> 9.17.3, also
    affects 9.9.12-S1 -> 9.9.13-S1, 9.11.3-S1 -> 9.11.21-S1 of the BIND 9 Supported Preview Edition, An
    attacker who has been granted privileges to change a specific subset of the zone's content could abuse
    these unintended additional privileges to update other contents of the zone. (CVE-2020-8624)

  - cloud-init through 19.4 relies on Mersenne Twister for a random password, which makes it easier for
    attackers to predict passwords, because rand_str in cloudinit/util.py calls the random.choice function.
    (CVE-2020-8631)

  - In cloud-init through 19.4, rand_user_password in cloudinit/config/cc_set_passwords.py has a small default
    pwlen value, which makes it easier for attackers to guess passwords. (CVE-2020-8632)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vc_do_resize function in
    drivers/tty/vt/vt.c. (CVE-2020-8647)

  - There is a use-after-free vulnerability in the Linux kernel through 5.5.2 in the vgacon_invert_region
    function in drivers/video/console/vgacon.c. (CVE-2020-8649)

  - An issue was discovered in the Linux kernel 3.16 through 5.5.6. set_fdc in drivers/block/floppy.c leads to
    a wait_til_ready out-of-bounds read because the FDC index is not checked for errors before assigning it,
    aka CID-2e90ca68b0d2. (CVE-2020-9383)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.19.0.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb66440b");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17006");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5482");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.19.0.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.19.0.5 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.19.0.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.19.0.5 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
