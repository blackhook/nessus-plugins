#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164612);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2015-2716",
    "CVE-2015-8035",
    "CVE-2015-9289",
    "CVE-2016-5131",
    "CVE-2017-6519",
    "CVE-2017-11166",
    "CVE-2017-12805",
    "CVE-2017-12806",
    "CVE-2017-15412",
    "CVE-2017-15710",
    "CVE-2017-17807",
    "CVE-2017-18251",
    "CVE-2017-18252",
    "CVE-2017-18254",
    "CVE-2017-18258",
    "CVE-2017-18271",
    "CVE-2017-18273",
    "CVE-2017-1000476",
    "CVE-2018-1116",
    "CVE-2018-1301",
    "CVE-2018-4180",
    "CVE-2018-4181",
    "CVE-2018-4700",
    "CVE-2018-5745",
    "CVE-2018-7191",
    "CVE-2018-8804",
    "CVE-2018-9133",
    "CVE-2018-10177",
    "CVE-2018-10360",
    "CVE-2018-10804",
    "CVE-2018-10805",
    "CVE-2018-11656",
    "CVE-2018-12599",
    "CVE-2018-12600",
    "CVE-2018-13153",
    "CVE-2018-14404",
    "CVE-2018-14434",
    "CVE-2018-14435",
    "CVE-2018-14436",
    "CVE-2018-14437",
    "CVE-2018-14567",
    "CVE-2018-15587",
    "CVE-2018-15607",
    "CVE-2018-16328",
    "CVE-2018-16749",
    "CVE-2018-16750",
    "CVE-2018-17199",
    "CVE-2018-18066",
    "CVE-2018-18074",
    "CVE-2018-18544",
    "CVE-2018-19985",
    "CVE-2018-20060",
    "CVE-2018-20169",
    "CVE-2018-20467",
    "CVE-2018-20852",
    "CVE-2019-0199",
    "CVE-2019-2737",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2805",
    "CVE-2019-3820",
    "CVE-2019-3890",
    "CVE-2019-3901",
    "CVE-2019-5436",
    "CVE-2019-6465",
    "CVE-2019-6477",
    "CVE-2019-7175",
    "CVE-2019-7397",
    "CVE-2019-7398",
    "CVE-2019-9503",
    "CVE-2019-9924",
    "CVE-2019-9956",
    "CVE-2019-10072",
    "CVE-2019-10131",
    "CVE-2019-10207",
    "CVE-2019-10638",
    "CVE-2019-10639",
    "CVE-2019-10650",
    "CVE-2019-11135",
    "CVE-2019-11190",
    "CVE-2019-11236",
    "CVE-2019-11324",
    "CVE-2019-11470",
    "CVE-2019-11472",
    "CVE-2019-11487",
    "CVE-2019-11597",
    "CVE-2019-11598",
    "CVE-2019-11884",
    "CVE-2019-12382",
    "CVE-2019-12418",
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12978",
    "CVE-2019-12979",
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13232",
    "CVE-2019-13233",
    "CVE-2019-13295",
    "CVE-2019-13297",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454",
    "CVE-2019-13648",
    "CVE-2019-14283",
    "CVE-2019-14815",
    "CVE-2019-14980",
    "CVE-2019-14981",
    "CVE-2019-15090",
    "CVE-2019-15139",
    "CVE-2019-15140",
    "CVE-2019-15141",
    "CVE-2019-15221",
    "CVE-2019-15916",
    "CVE-2019-16056",
    "CVE-2019-16708",
    "CVE-2019-16709",
    "CVE-2019-16710",
    "CVE-2019-16711",
    "CVE-2019-16712",
    "CVE-2019-16713",
    "CVE-2019-16746",
    "CVE-2019-17041",
    "CVE-2019-17042",
    "CVE-2019-17540",
    "CVE-2019-17541",
    "CVE-2019-17563",
    "CVE-2019-17569",
    "CVE-2019-17666",
    "CVE-2019-18660",
    "CVE-2019-19338",
    "CVE-2019-19948",
    "CVE-2019-19949",
    "CVE-2020-1935",
    "CVE-2020-1938",
    "CVE-2020-2754",
    "CVE-2020-2755",
    "CVE-2020-2756",
    "CVE-2020-2757",
    "CVE-2020-2767",
    "CVE-2020-2773",
    "CVE-2020-2778",
    "CVE-2020-2781",
    "CVE-2020-2800",
    "CVE-2020-2803",
    "CVE-2020-2805",
    "CVE-2020-2816",
    "CVE-2020-2830",
    "CVE-2020-5208",
    "CVE-2020-8616",
    "CVE-2020-8617",
    "CVE-2020-9484",
    "CVE-2020-10531",
    "CVE-2020-11996",
    "CVE-2020-13934",
    "CVE-2020-13935"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.17.1)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.17.1. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.17.1 advisory.

  - Buffer overflow in the XML parser in Mozilla Firefox before 38.0, Firefox ESR 31.x before 31.7, and
    Thunderbird before 31.7 allows remote attackers to execute arbitrary code by providing a large amount of
    compressed XML data, a related issue to CVE-2015-1283. (CVE-2015-2716)

  - The xz_decomp function in xzlib.c in libxml2 2.9.1 does not properly detect compression errors, which
    allows context-dependent attackers to cause a denial of service (process hang) via crafted XML data.
    (CVE-2015-8035)

  - In the Linux kernel before 4.1.4, a buffer overflow occurs when checking userspace params in
    drivers/media/dvb-frontends/cx24116.c. The maximum size for a DiSEqC command is 6, according to the
    userspace API. However, the code allows larger values such as 23. (CVE-2015-9289)

  - Use-after-free vulnerability in libxml2 through 2.9.4, as used in Google Chrome before 52.0.2743.82,
    allows remote attackers to cause a denial of service or possibly have unspecified other impact via vectors
    related to the XPointer range-to function. (CVE-2016-5131)

  - ImageMagick 7.0.7-12 Q16, a CPU exhaustion vulnerability was found in the function ReadDDSInfo in
    coders/dds.c, which allows attackers to cause a denial of service. (CVE-2017-1000476)

  - The ReadXWDImage function in coders\xwd.c in ImageMagick 7.0.5-6 has a memory leak vulnerability that can
    cause memory exhaustion via a crafted length (number of color-map entries) field in the header of an XWD
    file. (CVE-2017-11166)

  - In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in the function ReadTIFFImage, which
    allows attackers to cause a denial of service. (CVE-2017-12805)

  - In ImageMagick 7.0.6-6, a memory exhaustion vulnerability was found in the function format8BIM, which
    allows attackers to cause a denial of service. (CVE-2017-12806)

  - Use after free in libxml2 before 2.9.5, as used in Google Chrome prior to 63.0.3239.84 and other products,
    allowed a remote attacker to potentially exploit heap corruption via a crafted HTML page. (CVE-2017-15412)

  - In Apache httpd 2.0.23 to 2.0.65, 2.2.0 to 2.2.34, and 2.4.0 to 2.4.29, mod_authnz_ldap, if configured
    with AuthLDAPCharsetConfig, uses the Accept-Language header value to lookup the right charset encoding
    when verifying the user's credentials. If the header value is not present in the charset conversion table,
    a fallback mechanism is used to truncate it to a two characters value to allow a quick retry (for example,
    'en-US' is truncated to 'en'). A header value of less than two characters forces an out of bound write of
    one NUL byte to a memory location that is not part of the string. In the worst case, quite unlikely, the
    process would crash which could be used as a Denial of Service attack. In the more likely case, this
    memory is already reserved for future use and the issue has no effect at all. (CVE-2017-15710)

  - The KEYS subsystem in the Linux kernel before 4.14.6 omitted an access-control check when adding a key to
    the current task's default request-key keyring via the request_key() system call, allowing a local user
    to use a sequence of crafted system calls to add keys to a keyring with only Search permission (not Write
    permission) to that keyring, related to construct_get_dest_keyring() in security/keys/request_key.c.
    (CVE-2017-17807)

  - An issue was discovered in ImageMagick 7.0.7. A memory leak vulnerability was found in the function
    ReadPCDImage in coders/pcd.c, which allow remote attackers to cause a denial of service via a crafted
    file. (CVE-2017-18251)

  - An issue was discovered in ImageMagick 7.0.7. The MogrifyImageList function in MagickWand/mogrify.c allows
    attackers to cause a denial of service (assertion failure and application exit in ReplaceImageInList) via
    a crafted file. (CVE-2017-18252)

  - An issue was discovered in ImageMagick 7.0.7. A memory leak vulnerability was found in the function
    WriteGIFImage in coders/gif.c, which allow remote attackers to cause a denial of service via a crafted
    file. (CVE-2017-18254)

  - The xz_head function in xzlib.c in libxml2 before 2.9.6 allows remote attackers to cause a denial of
    service (memory consumption) via a crafted LZMA file, because the decoder functionality does not restrict
    memory usage to what is required for a legitimate file. (CVE-2017-18258)

  - In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop vulnerability was found in the function
    ReadMIFFImage in coders/miff.c, which allows attackers to cause a denial of service (CPU exhaustion) via a
    crafted MIFF image file. (CVE-2017-18271)

  - In ImageMagick 7.0.7-16 Q16 x86_64 2017-12-22, an infinite loop vulnerability was found in the function
    ReadTXTImage in coders/txt.c, which allows attackers to cause a denial of service (CPU exhaustion) via a
    crafted image file that is mishandled in a GetImageIndexInList call. (CVE-2017-18273)

  - avahi-daemon in Avahi through 0.6.32 and 0.7 inadvertently responds to IPv6 unicast queries with source
    addresses that are not on-link, which allows remote attackers to cause a denial of service (traffic
    amplification) and may cause information leakage by obtaining potentially sensitive information from the
    responding device via port-5353 UDP packets. NOTE: this may overlap CVE-2015-2809. (CVE-2017-6519)

  - In ImageMagick 7.0.7-28, there is an infinite loop in the ReadOneMNGImage function of the coders/png.c
    file. Remote attackers could leverage this vulnerability to cause a denial of service via a crafted mng
    file. (CVE-2018-10177)

  - The do_core_note function in readelf.c in libmagic.a in file 5.33 allows remote attackers to cause a
    denial of service (out-of-bounds read and application crash) via a crafted ELF file. (CVE-2018-10360)

  - ImageMagick version 7.0.7-28 contains a memory leak in WriteTIFFImage in coders/tiff.c. (CVE-2018-10804)

  - ImageMagick version 7.0.7-28 contains a memory leak in ReadYCBCRImage in coders/ycbcr.c. (CVE-2018-10805)

  - A flaw was found in polkit before version 0.116. The implementation of the
    polkit_backend_interactive_authority_check_authorization function in polkitd allows to test for
    authentication and trigger authentication of unrelated processes owned by other users. This may result in
    a local DoS and information disclosure. (CVE-2018-1116)

  - In ImageMagick 7.0.7-20 Q16 x86_64, a memory leak vulnerability was found in the function ReadDCMImage in
    coders/dcm.c, which allows attackers to cause a denial of service via a crafted DCM image file.
    (CVE-2018-11656)

  - In ImageMagick 7.0.8-3 Q16, ReadBMPImage and WriteBMPImage in coders/bmp.c allow attackers to cause an out
    of bounds write via a crafted file. (CVE-2018-12599)

  - In ImageMagick 7.0.8-3 Q16, ReadDIBImage and WriteDIBImage in coders/dib.c allow attackers to cause an out
    of bounds write via a crafted file. (CVE-2018-12600)

  - A specially crafted request could have crashed the Apache HTTP Server prior to version 2.4.30, due to an
    out of bound access after a size limit is reached by reading the HTTP header. This vulnerability is
    considered very hard if not impossible to trigger in non-debug mode (both log and build level), so it is
    classified as low risk for common server usage. (CVE-2018-1301)

  - In ImageMagick 7.0.8-4, there is a memory leak in the XMagickCommand function in MagickCore/animate.c.
    (CVE-2018-13153)

  - A NULL pointer dereference vulnerability exists in the xpath.c:xmlXPathCompOpEval() function of libxml2
    through 2.9.8 when parsing an invalid XPath expression in the XPATH_OP_AND or XPATH_OP_OR case.
    Applications processing untrusted XSL format inputs with the use of the libxml2 library may be vulnerable
    to a denial of service attack due to a crash of the application. (CVE-2018-14404)

  - ImageMagick 7.0.8-4 has a memory leak for a colormap in WriteMPCImage in coders/mpc.c. (CVE-2018-14434)

  - ImageMagick 7.0.8-4 has a memory leak in DecodeImage in coders/pcd.c. (CVE-2018-14435)

  - ImageMagick 7.0.8-4 has a memory leak in ReadMIFFImage in coders/miff.c. (CVE-2018-14436)

  - ImageMagick 7.0.8-4 has a memory leak in parse8BIM in coders/meta.c. (CVE-2018-14437)

  - libxml2 2.9.8, if --with-lzma is used, allows remote attackers to cause a denial of service (infinite
    loop) via a crafted XML file that triggers LZMA_MEMLIMIT_ERROR, as demonstrated by xmllint, a different
    vulnerability than CVE-2015-8035 and CVE-2018-9251. (CVE-2018-14567)

  - GNOME Evolution through 3.28.2 is prone to OpenPGP signatures being spoofed for arbitrary messages using a
    specially crafted email that contains a valid signature from the entity to be impersonated as an
    attachment. (CVE-2018-15587)

  - In ImageMagick 7.0.8-11 Q16, a tiny input file 0x50 0x36 0x36 0x36 0x36 0x4c 0x36 0x38 0x36 0x36 0x36 0x36
    0x36 0x36 0x1f 0x35 0x50 0x00 can result in a hang of several minutes during which CPU and memory
    resources are consumed until ultimately an attempted large memory allocation fails. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted file. (CVE-2018-15607)

  - In ImageMagick before 7.0.8-8, a NULL pointer dereference exists in the CheckEventLogging function in
    MagickCore/log.c. (CVE-2018-16328)

  - In ImageMagick 7.0.7-29 and earlier, a missing NULL check in ReadOneJNGImage in coders/png.c allows an
    attacker to cause a denial of service (WriteBlob assertion failure and application exit) via a crafted
    file. (CVE-2018-16749)

  - In ImageMagick 7.0.7-29 and earlier, a memory leak in the formatIPTCfromBuffer function in coders/meta.c
    was found. (CVE-2018-16750)

  - In Apache HTTP Server 2.4 release 2.4.37 and prior, mod_session checks the session expiry time before
    decoding the session. This causes session expiry time to be ignored for mod_session_cookie sessions since
    the expiry time is loaded when the session is decoded. (CVE-2018-17199)

  - snmp_oid_compare in snmplib/snmp_api.c in Net-SNMP before 5.8 has a NULL Pointer Exception bug that can be
    used by an unauthenticated attacker to remotely cause the instance to crash via a crafted UDP packet,
    resulting in Denial of Service. (CVE-2018-18066)

  - The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon
    receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover
    credentials by sniffing the network. (CVE-2018-18074)

  - There is a memory leak in the function WriteMSLImage of coders/msl.c in ImageMagick 7.0.8-13 Q16, and the
    function ProcessMSLScript of coders/msl.c in GraphicsMagick before 1.3.31. (CVE-2018-18544)

  - The function hso_get_config_data in drivers/net/usb/hso.c in the Linux kernel through 4.19.8 reads if_num
    from the USB device (as a u8) and uses it to index a small array, resulting in an object out-of-bounds
    (OOB) read that potentially allows arbitrary read in the kernel address space. (CVE-2018-19985)

  - urllib3 before version 1.23 does not remove the Authorization HTTP header when following a cross-origin
    redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credentials in the
    Authorization header to be exposed to unintended hosts or transmitted in cleartext. (CVE-2018-20060)

  - An issue was discovered in the Linux kernel before 4.19.9. The USB subsystem mishandles size checks during
    the reading of an extra descriptor, related to __usb_get_extra_descriptor in drivers/usb/core/usb.c.
    (CVE-2018-20169)

  - In coders/bmp.c in ImageMagick before 7.0.8-16, an input file can result in an infinite loop and hang,
    with high CPU and memory consumption. Remote attackers could leverage this vulnerability to cause a denial
    of service via a crafted file. (CVE-2018-20467)

  - http.cookiejar.DefaultPolicy.domain_return_ok in Lib/http/cookiejar.py in Python before 3.7.3 does not
    correctly validate the domain: it can be tricked into sending existing cookies to the wrong server. An
    attacker may abuse this flaw by using a server with a hostname that has another valid hostname as a suffix
    (e.g., pythonicexample.com to steal cookies for example.com). When a program uses
    http.cookiejar.DefaultPolicy and tries to do an HTTP connection to an attacker-controlled server, existing
    cookies can be leaked to the attacker. This affects 2.x through 2.7.16, 3.x before 3.4.10, 3.5.x before
    3.5.7, 3.6.x before 3.6.9, and 3.7.x before 3.7.3. (CVE-2018-20852)

  - In macOS High Sierra before 10.13.5, an issue existed in CUPS. This issue was addressed with improved
    access restrictions. (CVE-2018-4180, CVE-2018-4181)

  - managed-keys is a feature which allows a BIND resolver to automatically maintain the keys used by trust
    anchors which operators configure for use in DNSSEC validation. Due to an error in the managed-keys
    feature it is possible for a BIND server which uses managed-keys to exit due to an assertion failure if,
    during key rollover, a trust anchor's keys are replaced with keys which use an unsupported algorithm.
    Versions affected: BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P1, 9.12.0 -> 9.12.3-P1, and versions
    9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 -> 9.13.6 of the 9.13
    development branch are also affected. Versions prior to BIND 9.9.0 have not been evaluated for
    vulnerability to CVE-2018-5745. (CVE-2018-5745)

  - In the tun subsystem in the Linux kernel before 4.13.14, dev_get_valid_name is not called before
    register_netdevice. This allows local users to cause a denial of service (NULL pointer dereference and
    panic) via an ioctl(TUNSETIFF) call with a dev name containing a / character. This is similar to
    CVE-2013-4343. (CVE-2018-7191)

  - WriteEPTImage in coders/ept.c in ImageMagick 7.0.7-25 Q16 allows remote attackers to cause a denial of
    service (MagickCore/memory.c double free and application crash) or possibly have unspecified other impact
    via a crafted file. (CVE-2018-8804)

  - ImageMagick 7.0.7-26 Q16 has excessive iteration in the DecodeLabImage and EncodeLabImage functions
    (coders/tiff.c), which results in a hang (tens of minutes) with a tiny PoC file. Remote attackers could
    leverage this vulnerability to cause a denial of service via a crafted tiff file. (CVE-2018-9133)

  - The HTTP/2 implementation in Apache Tomcat 9.0.0.M1 to 9.0.14 and 8.5.0 to 8.5.37 accepted streams with
    excessive numbers of SETTINGS frames and also permitted clients to keep streams open without
    reading/writing request/response data. By keeping streams open for requests that utilised the Servlet
    API's blocking I/O, clients were able to cause server-side threads to block eventually leading to thread
    exhaustion and a DoS. (CVE-2019-0199)

  - The fix for CVE-2019-0199 was incomplete and did not address HTTP/2 connection window exhaustion on write
    in Apache Tomcat versions 9.0.0.M1 to 9.0.19 and 8.5.0 to 8.5.40 . By not sending WINDOW_UPDATE messages
    for the connection window (stream 0) clients were able to cause server-side threads to block eventually
    leading to thread exhaustion and a DoS. (CVE-2019-10072)

  - An off-by-one read vulnerability was discovered in ImageMagick before version 7.0.7-28 in the
    formatIPTCfromBuffer function in coders/meta.c. A local attacker may use this flaw to read beyond the end
    of the buffer or to crash the program. (CVE-2019-10131)

  - A flaw was found in the Linux kernel's Bluetooth implementation of UART, all versions kernel 3.x.x before
    4.18.0 and kernel 5.x.x. An attacker with local access and write permissions to the Bluetooth hardware
    could use this flaw to issue a specially crafted ioctl function call and cause the system to crash.
    (CVE-2019-10207)

  - In the Linux kernel before 5.1.7, a device can be tracked by an attacker using the IP ID values the kernel
    produces for connection-less protocols (e.g., UDP and ICMP). When such traffic is sent to multiple
    destination IP addresses, it is possible to obtain hash collisions (of indices to the counter array) and
    thereby obtain the hashing key (via enumeration). An attack may be conducted by hosting a crafted web page
    that uses WebRTC or gQUIC to force UDP traffic to attacker-controlled IP addresses. (CVE-2019-10638)

  - The Linux kernel 4.x (starting from 4.1) and 5.x before 5.0.8 allows Information Exposure (partial kernel
    address disclosure), leading to a KASLR bypass. Specifically, it is possible to extract the KASLR kernel
    image offset using the IP ID values the kernel produces for connection-less protocols (e.g., UDP and
    ICMP). When such traffic is sent to multiple destination IP addresses, it is possible to obtain hash
    collisions (of indices to the counter array) and thereby obtain the hashing key (via enumeration). This
    key contains enough bits from a kernel address (of a static variable) so when the key is extracted (via
    enumeration), the offset of the kernel image is exposed. This attack can be carried out remotely, by the
    attacker forcing the target device to send UDP or ICMP (or certain other) traffic to attacker-controlled
    IP addresses. Forcing a server to send UDP traffic is trivial if the server is a DNS server. ICMP traffic
    is trivial if the server answers ICMP Echo requests (ping). For client targets, if the target visits the
    attacker's web page, then WebRTC or gQUIC can be used to force UDP traffic to attacker-controlled IP
    addresses. NOTE: this attack against KASLR became viable in 4.1 because IP ID generation was changed to
    have a dependency on an address associated with a network namespace. (CVE-2019-10639)

  - In ImageMagick 7.0.8-36 Q16, there is a heap-based buffer over-read in the function WriteTIFFImage of
    coders/tiff.c, which allows an attacker to cause a denial of service or information disclosure via a
    crafted image file. (CVE-2019-10650)

  - TSX Asynchronous Abort condition on some CPUs utilizing speculative execution may allow an authenticated
    user to potentially enable information disclosure via a side channel with local access. (CVE-2019-11135)

  - The Linux kernel before 4.8 allows local users to bypass ASLR on setuid programs (such as /bin/su) because
    install_exec_creds() is called too late in load_elf_binary() in fs/binfmt_elf.c, and thus the
    ptrace_may_access() check has a race condition when reading /proc/pid/stat. (CVE-2019-11190)

  - In the urllib3 library through 1.24.1 for Python, CRLF injection is possible if the attacker controls the
    request parameter. (CVE-2019-11236)

  - The urllib3 library before 1.24.2 for Python mishandles certain cases where the desired set of CA
    certificates is different from the OS store of CA certificates, which results in SSL connections
    succeeding in situations where a verification failure is the correct outcome. This is related to use of
    the ssl_context, ca_certs, or ca_certs_dir argument. (CVE-2019-11324)

  - The cineon parsing component in ImageMagick 7.0.8-26 Q16 allows attackers to cause a denial-of-service
    (uncontrolled resource consumption) by crafting a Cineon image with an incorrect claimed image size. This
    occurs because ReadCINImage in coders/cin.c lacks a check for insufficient image data in a file.
    (CVE-2019-11470)

  - ReadXWDImage in coders/xwd.c in the XWD image parsing component of ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (divide-by-zero error) by crafting an XWD image file in which the
    header indicates neither LSB first nor MSB first. (CVE-2019-11472)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in the function WriteTIFFImage of
    coders/tiff.c, which allows an attacker to cause a denial of service or possibly information disclosure
    via a crafted image file. (CVE-2019-11597)

  - In ImageMagick 7.0.8-40 Q16, there is a heap-based buffer over-read in the function WritePNMImage of
    coders/pnm.c, which allows an attacker to cause a denial of service or possibly information disclosure via
    a crafted image file. This is related to SetGrayscaleImage in MagickCore/quantize.c. (CVE-2019-11598)

  - The do_hidp_sock_ioctl function in net/bluetooth/hidp/sock.c in the Linux kernel before 5.0.15 allows a
    local user to obtain potentially sensitive information from kernel stack memory via a HIDPCONNADD command,
    because a name field may not end with a '\0' character. (CVE-2019-11884)

  - ** DISPUTED ** An issue was discovered in drm_load_edid_firmware in drivers/gpu/drm/drm_edid_load.c in the
    Linux kernel through 5.1.5. There is an unchecked kstrdup of fwstr, which might allow an attacker to cause
    a denial of service (NULL pointer dereference and system crash). NOTE: The vendor disputes this issues as
    not being a vulnerability because kstrdup() returning NULL is handled sufficiently and there is no chance
    for a NULL pointer dereference. (CVE-2019-12382)

  - When Apache Tomcat 9.0.0.M1 to 9.0.28, 8.5.0 to 8.5.47, 7.0.0 and 7.0.97 is configured with the JMX Remote
    Lifecycle Listener, a local attacker without access to the Tomcat process or configuration files is able
    to manipulate the RMI registry to perform a man-in-the-middle attack to capture user names and passwords
    used to access the JMX interface. The attacker can then use these credentials to access the JMX interface
    and gain complete control over the Tomcat instance. (CVE-2019-12418)

  - A NULL pointer dereference in the function ReadPANGOImage in coders/pango.c and the function ReadVIDImage
    in coders/vid.c in ImageMagick 7.0.8-34 allows remote attackers to cause a denial of service via a crafted
    image. (CVE-2019-12974)

  - ImageMagick 7.0.8-34 has a memory leak vulnerability in the WriteDPXImage function in coders/dpx.c.
    (CVE-2019-12975)

  - ImageMagick 7.0.8-34 has a memory leak in the ReadPCLImage function in coders/pcl.c. (CVE-2019-12976)

  - ImageMagick 7.0.8-34 has a use of uninitialized value vulnerability in the ReadPANGOImage function in
    coders/pango.c. (CVE-2019-12978)

  - ImageMagick 7.0.8-34 has a use of uninitialized value vulnerability in the SyncImageSettings function in
    MagickCore/image.c. This is related to AcquireImage in magick/image.c. (CVE-2019-12979)

  - ImageMagick before 7.0.8-50 has a memory leak vulnerability in the function ReadBMPImage in coders/bmp.c.
    (CVE-2019-13133)

  - ImageMagick before 7.0.8-50 has a memory leak vulnerability in the function ReadVIFFImage in
    coders/viff.c. (CVE-2019-13134)

  - ImageMagick before 7.0.8-50 has a use of uninitialized value vulnerability in the function ReadCUTImage
    in coders/cut.c. (CVE-2019-13135)

  - Info-ZIP UnZip 6.0 mishandles the overlapping of files inside a ZIP container, leading to denial of
    service (resource consumption), aka a better zip bomb issue. (CVE-2019-13232)

  - In arch/x86/lib/insn-eval.c in the Linux kernel before 5.1.9, there is a use-after-free for access to an
    LDT entry because of a race condition between modify_ldt() and a #BR exception for an MPX bounds
    violation. (CVE-2019-13233)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer over-read at MagickCore/threshold.c in
    AdaptiveThresholdImage because a width of zero is mishandled. (CVE-2019-13295)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer over-read at MagickCore/threshold.c in
    AdaptiveThresholdImage because a height of zero is mishandled. (CVE-2019-13297)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling columns. (CVE-2019-13300)

  - ImageMagick 7.0.8-50 Q16 has memory leaks in AcquireMagickMemory because of an AnnotateImage error.
    (CVE-2019-13301)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at coders/pnm.c in WritePNMImage because of a
    misplaced assignment. (CVE-2019-13304)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at coders/pnm.c in WritePNMImage because of a
    misplaced strncpy and an off-by-one error. (CVE-2019-13305)

  - ImageMagick 7.0.8-50 Q16 has a stack-based buffer overflow at coders/pnm.c in WritePNMImage because of
    off-by-one errors. (CVE-2019-13306)

  - ImageMagick 7.0.8-50 Q16 has a heap-based buffer overflow at MagickCore/statistic.c in EvaluateImages
    because of mishandling rows. (CVE-2019-13307)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory because of mishandling the NoSuchImage
    error in CLIListOperatorImages in MagickWand/operation.c. (CVE-2019-13309)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory because of an error in
    MagickWand/mogrify.c. (CVE-2019-13310)

  - ImageMagick 7.0.8-50 Q16 has memory leaks at AcquireMagickMemory because of a wand/mogrify.c error.
    (CVE-2019-13311)

  - ImageMagick 7.0.8-54 Q16 allows Division by Zero in RemoveDuplicateLayers in MagickCore/layer.c.
    (CVE-2019-13454)

  - In the Linux kernel through 5.2.1 on the powerpc platform, when hardware transactional memory is disabled,
    a local user can cause a denial of service (TM Bad Thing exception and system crash) via a sigreturn()
    system call that sends a crafted signal frame. This affects arch/powerpc/kernel/signal_32.c and
    arch/powerpc/kernel/signal_64.c. (CVE-2019-13648)

  - In the Linux kernel before 5.2.3, set_geometry in drivers/block/floppy.c does not validate the sect and
    head fields, as demonstrated by an integer overflow and out-of-bounds read. It can be triggered by an
    unprivileged local user when a floppy disk has been inserted. NOTE: QEMU creates the floppy device by
    default. (CVE-2019-14283)

  - A vulnerability was found in Linux Kernel, where a Heap Overflow was found in mwifiex_set_wmm_params()
    function of Marvell Wifi Driver. (CVE-2019-14815)

  - In ImageMagick 7.x before 7.0.8-42 and 6.x before 6.9.10-42, there is a use after free vulnerability in
    the UnmapBlob function that allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14980)

  - In ImageMagick 7.x before 7.0.8-41 and 6.x before 6.9.10-41, there is a divide-by-zero vulnerability in
    the MeanShiftImage function. It allows an attacker to cause a denial of service by sending a crafted file.
    (CVE-2019-14981)

  - An issue was discovered in drivers/scsi/qedi/qedi_dbg.c in the Linux kernel before 5.1.12. In the
    qedi_dbg_* family of functions, there is an out-of-bounds read. (CVE-2019-15090)

  - The XWD image (X Window System window dumping file) parsing component in ImageMagick 7.0.8-41 Q16 allows
    attackers to cause a denial-of-service (application crash resulting from an out-of-bounds Read) in
    ReadXWDImage in coders/xwd.c by crafting a corrupted XWD image file, a different vulnerability than
    CVE-2019-11472. (CVE-2019-15139)

  - coders/mat.c in ImageMagick 7.0.8-43 Q16 allows remote attackers to cause a denial of service (use-after-
    free and application crash) or possibly have unspecified other impact by crafting a Matlab image file that
    is mishandled in ReadImage in MagickCore/constitute.c. (CVE-2019-15140)

  - WriteTIFFImage in coders/tiff.c in ImageMagick 7.0.8-43 Q16 allows attackers to cause a denial-of-service
    (application crash resulting from a heap-based buffer over-read) via a crafted TIFF image file, related to
    TIFFRewriteDirectory, TIFFWriteDirectory, TIFFWriteDirectorySec, and TIFFWriteDirectoryTagColormap in
    tif_dirwrite.c of LibTIFF. NOTE: this occurs because of an incomplete fix for CVE-2019-11597.
    (CVE-2019-15141)

  - An issue was discovered in the Linux kernel before 5.1.17. There is a NULL pointer dereference caused by a
    malicious USB device in the sound/usb/line6/pcm.c driver. (CVE-2019-15221)

  - An issue was discovered in the Linux kernel before 5.0.1. There is a memory leak in
    register_queue_kobjects() in net/core/net-sysfs.c, which will cause denial of service. (CVE-2019-15916)

  - An issue was discovered in Python through 2.7.16, 3.x through 3.5.7, 3.6.x through 3.6.9, and 3.7.x
    through 3.7.4. The email module wrongly parses email addresses that contain multiple @ characters. An
    application that uses the email module and implements some kind of checks on the From/To headers of a
    message could be tricked into accepting an email address that should be denied. An attack may be the same
    as in CVE-2019-11340; however, this CVE applies to Python more generally. (CVE-2019-16056)

  - ImageMagick 7.0.8-35 has a memory leak in magick/xwindow.c, related to XCreateImage. (CVE-2019-16708)

  - ImageMagick 7.0.8-35 has a memory leak in coders/dps.c, as demonstrated by XCreateImage. (CVE-2019-16709)

  - ImageMagick 7.0.8-35 has a memory leak in coders/dot.c, as demonstrated by AcquireMagickMemory in
    MagickCore/memory.c. (CVE-2019-16710)

  - ImageMagick 7.0.8-40 has a memory leak in Huffman2DEncodeImage in coders/ps2.c. (CVE-2019-16711)

  - ImageMagick 7.0.8-43 has a memory leak in Huffman2DEncodeImage in coders/ps3.c, as demonstrated by
    WritePS3Image. (CVE-2019-16712)

  - ImageMagick 7.0.8-43 has a memory leak in coders/dot.c, as demonstrated by PingImage in
    MagickCore/constitute.c. (CVE-2019-16713)

  - An issue was discovered in net/wireless/nl80211.c in the Linux kernel through 5.2.17. It does not check
    the length of variable elements in a beacon head, leading to a buffer overflow. (CVE-2019-16746)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmaixforwardedfrom/pmaixforwardedfrom.c has a heap
    overflow in the parser for AIX log messages. The parser tries to locate a log message delimiter (in this
    case, a space or a colon) but fails to account for strings that do not satisfy this constraint. If the
    string does not match, then the variable lenMsg will reach the value zero and will skip the sanity check
    that detects invalid log messages. The message will then be considered valid, and the parser will eat up
    the nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was
    zero and now becomes minus one. The following step in the parser is to shift left the contents of the
    message. To do this, it will call memmove with the right pointers to the target and destination strings,
    but the lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17041)

  - An issue was discovered in Rsyslog v8.1908.0. contrib/pmcisconames/pmcisconames.c has a heap overflow in
    the parser for Cisco log messages. The parser tries to locate a log message delimiter (in this case, a
    space or a colon), but fails to account for strings that do not satisfy this constraint. If the string
    does not match, then the variable lenMsg will reach the value zero and will skip the sanity check that
    detects invalid log messages. The message will then be considered valid, and the parser will eat up the
    nonexistent colon delimiter. In doing so, it will decrement lenMsg, a signed integer, whose value was zero
    and now becomes minus one. The following step in the parser is to shift left the contents of the message.
    To do this, it will call memmove with the right pointers to the target and destination strings, but the
    lenMsg will now be interpreted as a huge value, causing a heap overflow. (CVE-2019-17042)

  - ImageMagick before 7.0.8-54 has a heap-based buffer overflow in ReadPSInfo in coders/ps.c.
    (CVE-2019-17540)

  - ImageMagick before 7.0.8-55 has a use-after-free in DestroyStringInfo in MagickCore/string.c because the
    error manager is mishandled in coders/jpeg.c. (CVE-2019-17541)

  - When using FORM authentication with Apache Tomcat 9.0.0.M1 to 9.0.29, 8.5.0 to 8.5.49 and 7.0.0 to 7.0.98
    there was a narrow window where an attacker could perform a session fixation attack. The window was
    considered too narrow for an exploit to be practical but, erring on the side of caution, this issue has
    been treated as a security vulnerability. (CVE-2019-17563)

  - The refactoring present in Apache Tomcat 9.0.28 to 9.0.30, 8.5.48 to 8.5.50 and 7.0.98 to 7.0.99
    introduced a regression. The result of the regression was that invalid Transfer-Encoding headers were
    incorrectly processed leading to a possibility of HTTP Request Smuggling if Tomcat was located behind a
    reverse proxy that incorrectly handled the invalid Transfer-Encoding header in a particular manner. Such a
    reverse proxy is considered unlikely. (CVE-2019-17569)

  - rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a
    certain upper-bound check, leading to a buffer overflow. (CVE-2019-17666)

  - The Linux kernel before 5.4.1 on powerpc allows Information Exposure because the Spectre-RSB mitigation is
    not in place for all applicable CPUs, aka CID-39e72bf96f58. This is related to
    arch/powerpc/kernel/entry_64.S and arch/powerpc/kernel/security.c. (CVE-2019-18660)

  - A flaw was found in the fix for CVE-2019-11135, in the Linux upstream kernel versions before 5.5 where,
    the way Intel CPUs handle speculative execution of instructions when a TSX Asynchronous Abort (TAA) error
    occurs. When a guest is running on a host CPU affected by the TAA flaw (TAA_NO=0), but is not affected by
    the MDS issue (MDS_NO=1), the guest was to clear the affected buffers by using a VERW instruction
    mechanism. But when the MDS_NO=1 bit was exported to the guests, the guests did not use the VERW mechanism
    to clear the affected buffers. This issue affects guests running on Cascade Lake CPUs and requires that
    host has 'TSX' enabled. Confidentiality of data is the highest threat associated with this vulnerability.
    (CVE-2019-19338)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer overflow in the function WriteSGIImage of
    coders/sgi.c. (CVE-2019-19948)

  - In ImageMagick 7.0.8-43 Q16, there is a heap-based buffer over-read in the function WritePNGImage of
    coders/png.c, related to Magick_png_write_raw_profile and LocaleNCompare. (CVE-2019-19949)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server : Pluggable Auth).
    Supported versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily
    exploitable vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2737)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily
    exploitable vulnerability allows high privileged attacker with logon to the infrastructure where MySQL
    Server executes to compromise MySQL Server. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server as well
    as unauthorized update, insert or delete access to some of MySQL Server accessible data. (CVE-2019-2739)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: XML). Supported
    versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2740)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Parser). Supported
    versions that are affected are 5.6.44 and prior, 5.7.26 and prior and 8.0.16 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2805)

  - It was discovered that the gnome-shell lock screen since version 3.15.91 did not properly restrict all
    contextual actions. An attacker with physical access to a locked workstation could invoke certain keyboard
    shortcuts, and potentially other actions. (CVE-2019-3820)

  - It was discovered evolution-ews before 3.31.3 does not check the validity of SSL certificates. An attacker
    could abuse this flaw to get confidential information by tricking the user into connecting to a fake
    server without the user noticing the difference. (CVE-2019-3890)

  - A race condition in perf_event_open() allows local attackers to leak sensitive data from setuid programs.
    As no relevant locks (in particular the cred_guard_mutex) are held during the ptrace_may_access() call, it
    is possible for the specified target task to perform an execve() syscall with setuid execution before
    perf_event_alloc() actually attaches to it, allowing an attacker to bypass the ptrace_may_access() check
    and the perf_event_exit_task(current) call that is performed in install_exec_creds() during privileged
    execve() calls. This issue affects kernel versions before 4.8. (CVE-2019-3901)

  - A heap buffer overflow in the TFTP receiving code allows for DoS or arbitrary code execution in libcurl
    versions 7.19.4 through 7.64.1. (CVE-2019-5436)

  - Controls for zone transfers may not be properly applied to Dynamically Loadable Zones (DLZs) if the zones
    are writable Versions affected: BIND 9.9.0 -> 9.10.8-P1, 9.11.0 -> 9.11.5-P2, 9.12.0 -> 9.12.3-P2, and
    versions 9.9.3-S1 -> 9.11.5-S3 of BIND 9 Supported Preview Edition. Versions 9.13.0 -> 9.13.6 of the 9.13
    development branch are also affected. Versions prior to BIND 9.9.0 have not been evaluated for
    vulnerability to CVE-2019-6465. (CVE-2019-6465)

  - With pipelining enabled each incoming query on a TCP connection requires a similar resource allocation to
    a query received via UDP or via TCP without pipelining enabled. A client using a TCP-pipelined connection
    to a server could consume more resources than the server has been provisioned to handle. When a TCP
    connection with a large number of pipelined queries is closed, the load on the server releasing these
    multiple resources can cause it to become unresponsive, even for queries that can be answered
    authoritatively or from cache. (This is most likely to be perceived as an intermittent server problem).
    (CVE-2019-6477)

  - In ImageMagick before 7.0.8-25, some memory leaks exist in DecodeImage in coders/pcd.c. (CVE-2019-7175)

  - In ImageMagick before 7.0.8-25 and GraphicsMagick through 1.3.31, several memory leaks exist in
    WritePDFImage in coders/pdf.c. (CVE-2019-7397)

  - In ImageMagick before 7.0.8-25, a memory leak exists in WriteDIBImage in coders/dib.c. (CVE-2019-7398)

  - The Broadcom brcmfmac WiFi driver prior to commit a4176ec356c73a46c07c181c6d04039fafa34a9f is vulnerable
    to a frame validation bypass. If the brcmfmac driver receives a firmware event frame from a remote source,
    the is_wlc_event_frame function will cause this frame to be discarded and unprocessed. If the driver
    receives the firmware event frame from the host, the appropriate handler is called. This frame validation
    can be bypassed if the bus used is USB (for instance by a wifi dongle). This can allow firmware event
    frames from a remote source to be processed. In the worst case scenario, by sending specially-crafted WiFi
    packets, a remote, unauthenticated attacker may be able to execute arbitrary code on a vulnerable system.
    More typically, this vulnerability will result in denial-of-service conditions. (CVE-2019-9503)

  - rbash in Bash before 4.4-beta2 did not prevent the shell user from modifying BASH_CMDS, thus allowing the
    user to execute any command with the permissions of the shell. (CVE-2019-9924)

  - In ImageMagick 7.0.8-35 Q16, there is a stack-based buffer overflow in the function PopHexPixel of
    coders/ps.c, which allows an attacker to cause a denial of service or code execution via a crafted image
    file. (CVE-2019-9956)

  - An issue was discovered in International Components for Unicode (ICU) for C/C++ through 66.1. An integer
    overflow, leading to a heap-based buffer overflow, exists in the UnicodeString::doAppend() function in
    common/unistr.cpp. (CVE-2020-10531)

  - A specially crafted sequence of HTTP/2 requests sent to Apache Tomcat 10.0.0-M1 to 10.0.0-M5, 9.0.0.M1 to
    9.0.35 and 8.5.0 to 8.5.55 could trigger high CPU usage for several seconds. If a sufficient number of
    such requests were made on concurrent HTTP/2 connections, the server could become unresponsive.
    (CVE-2020-11996)

  - An h2c direct connection to Apache Tomcat 10.0.0-M1 to 10.0.0-M6, 9.0.0.M5 to 9.0.36 and 8.5.1 to 8.5.56
    did not release the HTTP/1.1 processor after the upgrade to HTTP/2. If a sufficient number of such
    requests were made, an OutOfMemoryException could occur leading to a denial of service. (CVE-2020-13934)

  - The payload length in a WebSocket frame was not correctly validated in Apache Tomcat 10.0.0-M1 to
    10.0.0-M6, 9.0.0.M1 to 9.0.36, 8.5.0 to 8.5.56 and 7.0.27 to 7.0.104. Invalid payload lengths could
    trigger an infinite loop. Multiple requests with invalid payload lengths could lead to a denial of
    service. (CVE-2020-13935)

  - In Apache Tomcat 9.0.0.M1 to 9.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99 the HTTP header parsing code used
    an approach to end-of-line parsing that allowed some invalid HTTP headers to be parsed as valid. This led
    to a possibility of HTTP Request Smuggling if Tomcat was located behind a reverse proxy that incorrectly
    handled the invalid Transfer-Encoding header in a particular manner. Such a reverse proxy is considered
    unlikely. (CVE-2020-1935)

  - When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to
    Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP
    connection. If such connections are available to an attacker, they can be exploited in ways that may be
    surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped
    with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected
    (and recommended in the security guide) that this Connector would be disabled if not required. This
    vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the
    web application - processing any file in the web application as a JSP Further, if the web application
    allowed file upload and stored those files within the web application (or the attacker was able to control
    the content of the web application by some other means) then this, along with the ability to process a
    file as a JSP, made remote code execution possible. It is important to note that mitigation is only
    required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth
    approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to
    Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP
    Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading
    to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
    (CVE-2020-1938)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Scripting). Supported
    versions that are affected are Java SE: 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: Applies to
    client and server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2020-2754, CVE-2020-2755)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Serialization).
    Supported versions that are affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
    Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: Applies to client and server deployment of Java. This vulnerability can be exploited through
    sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying
    data to APIs in the specified Component without using sandboxed Java Web Start applications or sandboxed
    Java applets, such as through a web service. (CVE-2020-2756, CVE-2020-2757)

  - Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are
    affected are Java SE: 11.0.6 and 14. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result
    in unauthorized update, insert or delete access to some of Java SE accessible data as well as unauthorized
    read access to a subset of Java SE accessible data. Note: Applies to client and server deployment of Java.
    This vulnerability can be exploited through sandboxed Java Web Start applications and sandboxed Java
    applets. It can also be exploited by supplying data to APIs in the specified Component without using
    sandboxed Java Web Start applications or sandboxed Java applets, such as through a web service.
    (CVE-2020-2767)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Security). Supported
    versions that are affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: Applies to
    client and server deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start
    applications and sandboxed Java applets. It can also be exploited by supplying data to APIs in the
    specified Component without using sandboxed Java Web Start applications or sandboxed Java applets, such as
    through a web service. (CVE-2020-2773)

  - Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are
    affected are Java SE: 11.0.6 and 14. Difficult to exploit vulnerability allows unauthenticated attacker
    with network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result
    in unauthorized read access to a subset of Java SE accessible data. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-2778)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: JSSE). Supported
    versions that are affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Easily
    exploitable vulnerability allows unauthenticated attacker with network access via HTTPS to compromise Java
    SE, Java SE Embedded. Successful attacks of this vulnerability can result in unauthorized ability to cause
    a partial denial of service (partial DOS) of Java SE, Java SE Embedded. Note: Applies to client and server
    deployment of Java. This vulnerability can be exploited through sandboxed Java Web Start applications and
    sandboxed Java applets. It can also be exploited by supplying data to APIs in the specified Component
    without using sandboxed Java Web Start applications or sandboxed Java applets, such as through a web
    service. (CVE-2020-2781)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Lightweight HTTP
    Server). Supported versions that are affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded:
    8u241. Difficult to exploit vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized update, insert or delete access to some of Java SE, Java SE Embedded accessible data as well
    as unauthorized read access to a subset of Java SE, Java SE Embedded accessible data. Note: This
    vulnerability can only be exploited by supplying data to APIs in the specified Component without using
    Untrusted Java Web Start applications or Untrusted Java applets, such as through a web service.
    (CVE-2020-2800)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Libraries). Supported
    versions that are affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241. Difficult to
    exploit vulnerability allows unauthenticated attacker with network access via multiple protocols to
    compromise Java SE, Java SE Embedded. Successful attacks require human interaction from a person other
    than the attacker and while the vulnerability is in Java SE, Java SE Embedded, attacks may significantly
    impact additional products. Successful attacks of this vulnerability can result in takeover of Java SE,
    Java SE Embedded. Note: This vulnerability applies to Java deployments, typically in clients running
    sandboxed Java Web Start applications or sandboxed Java applets, that load and run untrusted code (e.g.,
    code that comes from the internet) and rely on the Java sandbox for security. This vulnerability does not
    apply to Java deployments, typically in servers, that load and run only trusted code (e.g., code installed
    by an administrator). (CVE-2020-2803, CVE-2020-2805)

  - Vulnerability in the Java SE product of Oracle Java SE (component: JSSE). Supported versions that are
    affected are Java SE: 11.0.6 and 14. Easily exploitable vulnerability allows unauthenticated attacker with
    network access via HTTPS to compromise Java SE. Successful attacks of this vulnerability can result in
    unauthorized creation, deletion or modification access to critical data or all Java SE accessible data.
    Note: This vulnerability can only be exploited by supplying data to APIs in the specified Component
    without using Untrusted Java Web Start applications or Untrusted Java applets, such as through a web
    service. (CVE-2020-2816)

  - Vulnerability in the Java SE, Java SE Embedded product of Oracle Java SE (component: Concurrency).
    Supported versions that are affected are Java SE: 7u251, 8u241, 11.0.6 and 14; Java SE Embedded: 8u241.
    Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple
    protocols to compromise Java SE, Java SE Embedded. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of service (partial DOS) of Java SE, Java SE Embedded.
    Note: Applies to client and server deployment of Java. This vulnerability can be exploited through
    sandboxed Java Web Start applications and sandboxed Java applets. It can also be exploited by supplying
    data to APIs in the specified Component without using sandboxed Java Web Start applications or sandboxed
    Java applets, such as through a web service. (CVE-2020-2830)

  - It's been found that multiple functions in ipmitool before 1.8.19 neglect proper checking of the data
    received from a remote LAN party, which may lead to buffer overflows and potentially to remote code
    execution on the ipmitool side. This is especially dangerous if ipmitool is run as a privileged user. This
    problem is fixed in version 1.8.19. (CVE-2020-5208)

  - A malicious actor who intentionally exploits this lack of effective limitation on the number of fetches
    performed when processing referrals can, through the use of specially crafted referrals, cause a recursing
    server to issue a very large number of fetches in an attempt to process the referral. This has at least
    two potential effects: The performance of the recursing server can potentially be degraded by the
    additional work required to perform these fetches, and The attacker can exploit this behavior to use the
    recursing server as a reflector in a reflection attack with a high amplification factor. (CVE-2020-8616)

  - Using a specially-crafted message, an attacker may potentially cause a BIND server to reach an
    inconsistent state if the attacker knows (or successfully guesses) the name of a TSIG key used by the
    server. Since BIND, by default, configures a local session key even on servers whose configuration does
    not otherwise make use of it, almost all current BIND servers are vulnerable. In releases of BIND dating
    from March 2018 and after, an assertion check in tsig.c detects this inconsistent state and deliberately
    exits. Prior to the introduction of the check the server would continue operating in an inconsistent
    state, with potentially harmful results. (CVE-2020-8617)

  - When using Apache Tomcat versions 10.0.0-M1 to 10.0.0-M4, 9.0.0.M1 to 9.0.34, 8.5.0 to 8.5.54 and 7.0.0 to
    7.0.103 if a) an attacker is able to control the contents and name of a file on the server; and b) the
    server is configured to use the PersistenceManager with a FileStore; and c) the PersistenceManager is
    configured with sessionAttributeValueClassNameFilter=null (the default unless a SecurityManager is used)
    or a sufficiently lax filter to allow the attacker provided object to be deserialized; and d) the attacker
    knows the relative file path from the storage location used by FileStore to the file the attacker has
    control over; then, using a specifically crafted request, the attacker will be able to trigger remote code
    execution via deserialization of the file under their control. Note that all of conditions a) to d) must
    be true for the attack to succeed. (CVE-2020-9484)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.17.1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3735bc17");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/03");
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
  { 'fixed_version' : '5.17.1', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.17.1 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.17.1', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.17.1 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
