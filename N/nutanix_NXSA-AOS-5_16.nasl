#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164573);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/17");

  script_cve_id(
    "CVE-2016-3186",
    "CVE-2016-3616",
    "CVE-2016-10739",
    "CVE-2016-10745",
    "CVE-2018-0495",
    "CVE-2018-0734",
    "CVE-2018-1122",
    "CVE-2018-3058",
    "CVE-2018-3063",
    "CVE-2018-3066",
    "CVE-2018-3081",
    "CVE-2018-3282",
    "CVE-2018-5741",
    "CVE-2018-7456",
    "CVE-2018-8905",
    "CVE-2018-10689",
    "CVE-2018-10779",
    "CVE-2018-10963",
    "CVE-2018-11212",
    "CVE-2018-11213",
    "CVE-2018-11214",
    "CVE-2018-11813",
    "CVE-2018-12327",
    "CVE-2018-12404",
    "CVE-2018-12641",
    "CVE-2018-12697",
    "CVE-2018-12900",
    "CVE-2018-14348",
    "CVE-2018-14498",
    "CVE-2018-14598",
    "CVE-2018-14599",
    "CVE-2018-14600",
    "CVE-2018-14618",
    "CVE-2018-14647",
    "CVE-2018-15473",
    "CVE-2018-15686",
    "CVE-2018-15853",
    "CVE-2018-15854",
    "CVE-2018-15855",
    "CVE-2018-15856",
    "CVE-2018-15857",
    "CVE-2018-15859",
    "CVE-2018-15861",
    "CVE-2018-15862",
    "CVE-2018-15863",
    "CVE-2018-15864",
    "CVE-2018-16062",
    "CVE-2018-16402",
    "CVE-2018-16403",
    "CVE-2018-16842",
    "CVE-2018-16866",
    "CVE-2018-16888",
    "CVE-2018-17100",
    "CVE-2018-17101",
    "CVE-2018-18074",
    "CVE-2018-18310",
    "CVE-2018-18384",
    "CVE-2018-18520",
    "CVE-2018-18521",
    "CVE-2018-18557",
    "CVE-2018-18584",
    "CVE-2018-18585",
    "CVE-2018-18661",
    "CVE-2018-19788",
    "CVE-2018-20060",
    "CVE-2018-1000876",
    "CVE-2019-0217",
    "CVE-2019-0220",
    "CVE-2019-1559",
    "CVE-2019-2503",
    "CVE-2019-2529",
    "CVE-2019-2614",
    "CVE-2019-2627",
    "CVE-2019-3858",
    "CVE-2019-3861",
    "CVE-2019-5010",
    "CVE-2019-6470",
    "CVE-2019-7149",
    "CVE-2019-7150",
    "CVE-2019-7664",
    "CVE-2019-7665",
    "CVE-2019-9740",
    "CVE-2019-9947",
    "CVE-2019-9948",
    "CVE-2019-11236",
    "CVE-2019-12735",
    "CVE-2019-1010238"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2019-0203");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.16)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.16. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-5.16 advisory.

  - In the GNU C Library (aka glibc or libc6) through 2.28, the getaddrinfo function would successfully parse
    a string that contained an IPv4 address followed by whitespace and arbitrary characters, which could lead
    applications to incorrectly assume that it had parsed a valid string, without the possibility of embedded
    HTTP headers or other potentially dangerous substrings. (CVE-2016-10739)

  - In Pallets Jinja before 2.8.1, str.format allows a sandbox escape. (CVE-2016-10745)

  - Buffer overflow in the readextension function in gif2tiff.c in LibTIFF 4.0.6 allows remote attackers to
    cause a denial of service (application crash) via a crafted GIF file. (CVE-2016-3186)

  - The cjpeg utility in libjpeg allows remote attackers to cause a denial of service (NULL pointer
    dereference and application crash) or execute arbitrary code via a crafted file. (CVE-2016-3616)

  - Libgcrypt before 1.7.10 and 1.8.x before 1.8.3 allows a memory-cache side-channel attack on ECDSA
    signatures that can be mitigated through the use of blinding during the signing process in the
    _gcry_ecc_ecdsa_sign function in cipher/ecc-ecdsa.c, aka the Return Of the Hidden Number Problem or ROHNP.
    To discover an ECDSA key, the attacker needs access to either the local machine or a different virtual
    machine on the same physical host. (CVE-2018-0495)

  - The OpenSSL DSA signature algorithm has been shown to be vulnerable to a timing side channel attack. An
    attacker could use variations in the signing algorithm to recover the private key. Fixed in OpenSSL 1.1.1a
    (Affected 1.1.1). Fixed in OpenSSL 1.1.0j (Affected 1.1.0-1.1.0i). Fixed in OpenSSL 1.0.2q (Affected
    1.0.2-1.0.2p). (CVE-2018-0734)

  - binutils version 2.32 and earlier contains a Integer Overflow vulnerability in objdump,
    bfd_get_dynamic_reloc_upper_bound,bfd_canonicalize_dynamic_reloc that can result in Integer overflow
    trigger heap overflow. Successful exploitation allows execution of arbitrary code.. This attack appear to
    be exploitable via Local. This vulnerability appears to have been fixed in after commit
    3a551c7a1b80fca579461774860574eabfd7f18f. (CVE-2018-1000876)

  - blktrace (aka Block IO Tracing) 1.2.0, as used with the Linux kernel and Android, has a buffer overflow in
    the dev_map_read function in btt/devmap.c because the device and devno arrays are too small, as
    demonstrated by an invalid free when using the btt program with a crafted file. (CVE-2018-10689)

  - TIFFWriteScanline in tif_write.c in LibTIFF 3.8.2 has a heap-based buffer over-read, as demonstrated by
    bmp2tiff. (CVE-2018-10779)

  - The TIFFWriteDirectorySec() function in tif_dirwrite.c in LibTIFF through 4.0.9 allows remote attackers to
    cause a denial of service (assertion failure and application crash) via a crafted file, a different
    vulnerability than CVE-2017-13726. (CVE-2018-10963)

  - An issue was discovered in libjpeg 9a and 9d. The alloc_sarray function in jmemmgr.c allows remote
    attackers to cause a denial of service (divide-by-zero error) via a crafted file. (CVE-2018-11212)

  - An issue was discovered in libjpeg 9a. The get_text_gray_row function in rdppm.c allows remote attackers
    to cause a denial of service (Segmentation fault) via a crafted file. (CVE-2018-11213)

  - An issue was discovered in libjpeg 9a. The get_text_rgb_row function in rdppm.c allows remote attackers to
    cause a denial of service (Segmentation fault) via a crafted file. (CVE-2018-11214)

  - procps-ng before version 3.3.15 is vulnerable to a local privilege escalation in top. If a user runs top
    with HOME unset in an attacker-controlled directory, the attacker could achieve privilege escalation by
    exploiting one of several vulnerabilities in the config_file() function. (CVE-2018-1122)

  - libjpeg 9c has a large loop because read_pixel in rdtarga.c mishandles EOF. (CVE-2018-11813)

  - Stack-based buffer overflow in ntpq and ntpdc of NTP version 4.2.8p11 allows an attacker to achieve code
    execution or escalate to higher privileges via a long string as the argument for an IPv4 or IPv6 command-
    line parameter. NOTE: It is unclear whether there are any common situations in which ntpq or ntpdc is used
    with a command line from an untrusted source. (CVE-2018-12327)

  - A cached side channel attack during handshakes using RSA encryption could allow for the decryption of
    encrypted content. This is a variant of the Adaptive Chosen Ciphertext attack (AKA Bleichenbacher attack)
    and affects all NSS versions prior to NSS 3.41. (CVE-2018-12404)

  - An issue was discovered in arm_pt in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30.
    Stack Exhaustion occurs in the C++ demangling functions provided by libiberty, and there are recursive
    stack frames: demangle_arm_hp_template, demangle_class_name, demangle_fund_type, do_type, do_arg,
    demangle_args, and demangle_nested_args. This can occur during execution of nm-new. (CVE-2018-12641)

  - A NULL pointer dereference (aka SEGV on unknown address 0x000000000000) was discovered in
    work_stuff_copy_to_from in cplus-dem.c in GNU libiberty, as distributed in GNU Binutils 2.30. This can
    occur during execution of objdump. (CVE-2018-12697)

  - Heap-based buffer overflow in the cpSeparateBufToContigBuf function in tiffcp.c in LibTIFF 3.9.3, 3.9.4,
    3.9.5, 3.9.6, 3.9.7, 4.0.0beta7, 4.0.0alpha4, 4.0.0alpha5, 4.0.0alpha6, 4.0.0, 4.0.1, 4.0.2, 4.0.3, 4.0.4,
    4.0.4beta, 4.0.5, 4.0.6, 4.0.7, 4.0.8 and 4.0.9 allows remote attackers to cause a denial of service
    (crash) or possibly have unspecified other impact via a crafted TIFF file. (CVE-2018-12900)

  - libcgroup up to and including 0.41 creates /var/log/cgred with mode 0666 regardless of the configured
    umask, leading to disclosure of information. (CVE-2018-14348)

  - get_8bit_row in rdbmp.c in libjpeg-turbo through 1.5.90 and MozJPEG through 3.3.1 allows attackers to
    cause a denial of service (heap-based buffer over-read and application crash) via a crafted 8-bit BMP in
    which one or more of the color indices is out of range for the number of palette entries. (CVE-2018-14498)

  - An issue was discovered in XListExtensions in ListExt.c in libX11 through 1.6.5. A malicious server can
    send a reply in which the first string overflows, causing a variable to be set to NULL that will be freed
    later on, leading to DoS (segmentation fault). (CVE-2018-14598)

  - An issue was discovered in libX11 through 1.6.5. The function XListExtensions in ListExt.c is vulnerable
    to an off-by-one error caused by malicious server responses, leading to DoS or possibly unspecified other
    impact. (CVE-2018-14599)

  - An issue was discovered in libX11 through 1.6.5. The function XListExtensions in ListExt.c interprets a
    variable as signed instead of unsigned, resulting in an out-of-bounds write (of up to 128 bytes), leading
    to DoS or remote code execution. (CVE-2018-14600)

  - curl before version 7.61.1 is vulnerable to a buffer overrun in the NTLM authentication code. The internal
    function Curl_ntlm_core_mk_nt_hash multiplies the length of the password by two (SUM) to figure out how
    large temporary storage area to allocate from the heap. The length value is then subsequently used to
    iterate over the password and generate output into the allocated storage buffer. On systems with a 32 bit
    size_t, the math to calculate SUM triggers an integer overflow when the password length exceeds 2GB (2^31
    bytes). This integer overflow usually causes a very small buffer to actually get allocated instead of the
    intended very huge one, making the use of that buffer end up in a heap buffer overflow. (This bug is
    almost identical to CVE-2017-8816.) (CVE-2018-14618)

  - Python's elementtree C accelerator failed to initialise Expat's hash salt during initialization. This
    could make it easy to conduct denial of service attacks against Expat by constructing an XML document that
    would cause pathological hash collisions in Expat's internal data structures, consuming large amounts CPU
    and RAM. The vulnerability exists in Python versions 3.7.0, 3.6.0 through 3.6.6, 3.5.0 through 3.5.6,
    3.4.0 through 3.4.9, 2.7.0 through 2.7.15. (CVE-2018-14647)

  - OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an
    invalid authenticating user until after the packet containing the request has been fully parsed, related
    to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c. (CVE-2018-15473)

  - A vulnerability in unit_deserialize of systemd allows an attacker to supply arbitrary state across systemd
    re-execution via NotifyAccess. This can be used to improperly influence systemd execution and possibly
    lead to root privilege escalation. Affected releases are systemd versions up to and including 239.
    (CVE-2018-15686)

  - Endless recursion exists in xkbcomp/expr.c in xkbcommon and libxkbcommon before 0.8.1, which could be used
    by local attackers to crash xkbcommon users by supplying a crafted keymap file that triggers boolean
    negation. (CVE-2018-15853)

  - Unchecked NULL pointer usage in xkbcommon before 0.8.1 could be used by local attackers to crash (NULL
    pointer dereference) the xkbcommon parser by supplying a crafted keymap file, because geometry tokens were
    desupported incorrectly. (CVE-2018-15854)

  - Unchecked NULL pointer usage in xkbcommon before 0.8.1 could be used by local attackers to crash (NULL
    pointer dereference) the xkbcommon parser by supplying a crafted keymap file, because the XkbFile for an
    xkb_geometry section was mishandled. (CVE-2018-15855)

  - An infinite loop when reaching EOL unexpectedly in compose/parser.c (aka the keymap parser) in xkbcommon
    before 0.8.1 could be used by local attackers to cause a denial of service during parsing of crafted
    keymap files. (CVE-2018-15856)

  - An invalid free in ExprAppendMultiKeysymList in xkbcomp/ast-build.c in xkbcommon before 0.8.1 could be
    used by local attackers to crash xkbcommon keymap parsers or possibly have unspecified other impact by
    supplying a crafted keymap file. (CVE-2018-15857)

  - Unchecked NULL pointer usage when parsing invalid atoms in ExprResolveLhs in xkbcomp/expr.c in xkbcommon
    before 0.8.2 could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by
    supplying a crafted keymap file, because lookup failures are mishandled. (CVE-2018-15859)

  - Unchecked NULL pointer usage in ExprResolveLhs in xkbcomp/expr.c in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap
    file that triggers an xkb_intern_atom failure. (CVE-2018-15861)

  - Unchecked NULL pointer usage in LookupModMask in xkbcomp/expr.c in xkbcommon before 0.8.2 could be used by
    local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap
    file with invalid virtual modifiers. (CVE-2018-15862)

  - Unchecked NULL pointer usage in ResolveStateAndPredicate in xkbcomp/compat.c in xkbcommon before 0.8.2
    could be used by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a
    crafted keymap file with a no-op modmask expression. (CVE-2018-15863)

  - Unchecked NULL pointer usage in resolve_keysym in xkbcomp/parser.y in xkbcommon before 0.8.2 could be used
    by local attackers to crash (NULL pointer dereference) the xkbcommon parser by supplying a crafted keymap
    file, because a map access attempt can occur for a map that was never created. (CVE-2018-15864)

  - dwarf_getaranges in dwarf_getaranges.c in libdw in elfutils before 2018-08-18 allows remote attackers to
    cause a denial of service (heap-based buffer over-read) via a crafted file. (CVE-2018-16062)

  - libelf/elf_end.c in elfutils 0.173 allows remote attackers to cause a denial of service (double free and
    application crash) or possibly have unspecified other impact because it tries to decompress twice.
    (CVE-2018-16402)

  - libdw in elfutils 0.173 checks the end of the attributes list incorrectly in dwarf_getabbrev in
    dwarf_getabbrev.c and dwarf_hasattr in dwarf_hasattr.c, leading to a heap-based buffer over-read and an
    application crash. (CVE-2018-16403)

  - Curl versions 7.14.1 through 7.61.1 are vulnerable to a heap-based buffer over-read in the
    tool_msgs.c:voutf() function that may result in information exposure and denial of service.
    (CVE-2018-16842)

  - An out of bounds read was discovered in systemd-journald in the way it parses log messages that terminate
    with a colon ':'. A local attacker can use this flaw to disclose process memory data. Versions from v221
    to v239 are vulnerable. (CVE-2018-16866)

  - It was discovered systemd does not correctly check the content of PIDFile files before using it to kill
    processes. When a service is run from an unprivileged user (e.g. User field set in the service file), a
    local attacker who is able to write to the PIDFile of the mentioned service may use this flaw to trick
    systemd into killing other services and/or privileged processes. Versions before v237 are vulnerable.
    (CVE-2018-16888)

  - An issue was discovered in LibTIFF 4.0.9. There is a int32 overflow in multiply_ms in tools/ppm2tiff.c,
    which can cause a denial of service (crash) or possibly have unspecified other impact via a crafted image
    file. (CVE-2018-17100)

  - An issue was discovered in LibTIFF 4.0.9. There are two out-of-bounds writes in cpTags in tools/tiff2bw.c
    and tools/pal2rgb.c, which can cause a denial of service (application crash) or possibly have unspecified
    other impact via a crafted image file. (CVE-2018-17101)

  - The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon
    receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover
    credentials by sniffing the network. (CVE-2018-18074)

  - An invalid memory address dereference was discovered in dwfl_segment_report_module.c in libdwfl in
    elfutils through v0.174. The vulnerability allows attackers to cause a denial of service (application
    crash) with a crafted ELF file, as demonstrated by consider_notes. (CVE-2018-18310)

  - Info-ZIP UnZip 6.0 has a buffer overflow in list.c, when a ZIP archive has a crafted relationship between
    the compressed-size value and the uncompressed-size value, because a buffer size is 10 and is supposed to
    be 12. (CVE-2018-18384)

  - An Invalid Memory Address Dereference exists in the function elf_end in libelf in elfutils through v0.174.
    Although eu-size is intended to support ar files inside ar files, handle_ar in size.c closes the outer ar
    file before handling all inner entries. The vulnerability allows attackers to cause a denial of service
    (application crash) with a crafted ELF file. (CVE-2018-18520)

  - Divide-by-zero vulnerabilities in the function arlib_add_symbols() in arlib.c in elfutils 0.174 allow
    remote attackers to cause a denial of service (application crash) with a crafted ELF file, as demonstrated
    by eu-ranlib, because a zero sh_entsize is mishandled. (CVE-2018-18521)

  - LibTIFF 3.9.3, 3.9.4, 3.9.5, 3.9.6, 3.9.7, 4.0.0alpha4, 4.0.0alpha5, 4.0.0alpha6, 4.0.0beta7, 4.0.0,
    4.0.1, 4.0.2, 4.0.3, 4.0.4, 4.0.4beta, 4.0.5, 4.0.6, 4.0.7, 4.0.8 and 4.0.9 (with JBIG enabled) decodes
    arbitrarily-sized JBIG into a buffer, ignoring the buffer size, which leads to a tif_jbig.c JBIGDecode
    out-of-bounds write. (CVE-2018-18557)

  - In mspack/cab.h in libmspack before 0.8alpha and cabextract before 1.8, the CAB block input buffer is one
    byte too small for the maximal Quantum block, leading to an out-of-bounds write. (CVE-2018-18584)

  - chmd_read_headers in mspack/chmd.c in libmspack before 0.8alpha accepts a filename that has '\0' as its
    first or second character (such as the /\0 name). (CVE-2018-18585)

  - An issue was discovered in LibTIFF 4.0.9. There is a NULL pointer dereference in the function LZWDecode in
    the file tif_lzw.c. (CVE-2018-18661)

  - A flaw was found in PolicyKit (aka polkit) 0.115 that allows a user with a uid greater than INT_MAX to
    successfully execute any systemctl command. (CVE-2018-19788)

  - urllib3 before version 1.23 does not remove the Authorization HTTP header when following a cross-origin
    redirect (i.e., a redirect that differs in host, port, or scheme). This can allow for credentials in the
    Authorization header to be exposed to unintended hosts or transmitted in cleartext. (CVE-2018-20060)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: MyISAM). Supported versions
    that are affected are 5.5.60 and prior, 5.6.40 and prior and 5.7.22 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized update, insert or delete
    access to some of MySQL Server accessible data. (CVE-2018-3058)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.5.60 and prior. Easily exploitable vulnerability allows high
    privileged attacker with network access via multiple protocols to compromise MySQL Server. Successful
    attacks of this vulnerability can result in unauthorized ability to cause a hang or frequently repeatable
    crash (complete DOS) of MySQL Server. (CVE-2018-3063)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Options). Supported
    versions that are affected are 5.5.60 and prior, 5.6.40 and prior and 5.7.22 and prior. Difficult to
    exploit vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized update,
    insert or delete access to some of MySQL Server accessible data as well as unauthorized read access to a
    subset of MySQL Server accessible data. (CVE-2018-3066)

  - Vulnerability in the MySQL Client component of Oracle MySQL (subcomponent: Client programs). Supported
    versions that are affected are 5.5.60 and prior, 5.6.40 and prior, 5.7.22 and prior and 8.0.11 and prior.
    Difficult to exploit vulnerability allows high privileged attacker with network access via multiple
    protocols to compromise MySQL Client. Successful attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Client as well as
    unauthorized update, insert or delete access to some of MySQL Client accessible data. (CVE-2018-3081)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Storage Engines).
    Supported versions that are affected are 5.5.61 and prior, 5.6.41 and prior, 5.7.23 and prior and 8.0.12
    and prior. Easily exploitable vulnerability allows high privileged attacker with network access via
    multiple protocols to compromise MySQL Server. Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently repeatable crash (complete DOS) of MySQL Server.
    (CVE-2018-3282)

  - To provide fine-grained controls over the ability to use Dynamic DNS (DDNS) to update records in a zone,
    BIND 9 provides a feature called update-policy. Various rules can be configured to limit the types of
    updates that can be performed by a client, depending on the key used when sending the update request.
    Unfortunately, some rule types were not initially documented, and when documentation for them was added to
    the Administrator Reference Manual (ARM) in change #3112, the language that was added to the ARM at that
    time incorrectly described the behavior of two rule types, krb5-subdomain and ms-subdomain. This incorrect
    documentation could mislead operators into believing that policies they had configured were more
    restrictive than they actually were. This affects BIND versions prior to BIND 9.11.5 and BIND 9.12.3.
    (CVE-2018-5741)

  - A NULL Pointer Dereference occurs in the function TIFFPrintDirectory in tif_print.c in LibTIFF 3.9.3,
    3.9.4, 3.9.5, 3.9.6, 3.9.7, 4.0.0alpha4, 4.0.0alpha5, 4.0.0alpha6, 4.0.0beta7, 4.0.0, 4.0.1, 4.0.2, 4.0.3,
    4.0.4, 4.0.4beta, 4.0.5, 4.0.6, 4.0.7, 4.0.8 and 4.0.9 when using the tiffinfo tool to print crafted TIFF
    information, a different vulnerability than CVE-2017-18013. (This affects an earlier part of the
    TIFFPrintDirectory function that was not addressed by the CVE-2017-18013 patch.) (CVE-2018-7456)

  - In LibTIFF 4.0.9, a heap-based buffer overflow occurs in the function LZWDecodeCompat in tif_lzw.c via a
    crafted TIFF file, as demonstrated by tiff2ps. (CVE-2018-8905)

  - In Apache HTTP Server 2.4 release 2.4.38 and prior, a race condition in mod_auth_digest when running in a
    threaded server could allow a user with valid credentials to authenticate using another username,
    bypassing configured access control restrictions. (CVE-2019-0217)

  - A vulnerability was found in Apache HTTP Server 2.4.0 to 2.4.38. When the path component of a request URL
    contains multiple consecutive slashes ('/'), directives such as LocationMatch and RewriteRule must account
    for duplicates in regular expressions while other aspects of the servers processing will implicitly
    collapse them. (CVE-2019-0220)

  - Gnome Pango 1.42 and later is affected by: Buffer Overflow. The impact is: The heap based buffer overflow
    can be used to get code execution. The component is: function name: pango_log2vis_get_embedding_levels,
    assignment of nchars and the loop condition. The attack vector is: Bug can be used when application pass
    invalid utf-8 strings to functions like pango_itemize. (CVE-2019-1010238)

  - In the urllib3 library through 1.24.1 for Python, CRLF injection is possible if the attacker controls the
    request parameter. (CVE-2019-11236)

  - getchar.c in Vim before 8.1.1365 and Neovim before 0.3.6 allows remote attackers to execute arbitrary OS
    commands via the :source! command in a modeline, as demonstrated by execute in Vim, and assert_fails or
    nvim_input in Neovim. (CVE-2019-12735)

  - If an application encounters a fatal protocol error and then calls SSL_shutdown() twice (once to send a
    close_notify, and once to receive one) then OpenSSL can respond differently to the calling application if
    a 0 byte record is received with invalid padding compared to if a 0 byte record is received with an
    invalid MAC. If the application then behaves differently based on that in a way that is detectable to the
    remote peer, then this amounts to a padding oracle that could be used to decrypt data. In order for this
    to be exploitable non-stitched ciphersuites must be in use. Stitched ciphersuites are optimised
    implementations of certain commonly used ciphersuites. Also the application must call SSL_shutdown() twice
    even if a protocol error has occurred (applications should not do this but some do anyway). Fixed in
    OpenSSL 1.0.2r (Affected 1.0.2-1.0.2q). (CVE-2019-1559)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Connection Handling).
    Supported versions that are affected are 5.6.42 and prior, 5.7.24 and prior and 8.0.13 and prior.
    Difficult to exploit vulnerability allows low privileged attacker with access to the physical
    communication segment attached to the hardware where the MySQL Server executes to compromise MySQL Server.
    Successful attacks of this vulnerability can result in unauthorized access to critical data or complete
    access to all MySQL Server accessible data and unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2503)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Optimizer). Supported
    versions that are affected are 5.6.42 and prior, 5.7.24 and prior and 8.0.13 and prior. Easily exploitable
    vulnerability allows low privileged attacker with network access via multiple protocols to compromise
    MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2529)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Replication). Supported
    versions that are affected are 5.6.43 and prior, 5.7.25 and prior and 8.0.15 and prior. Difficult to
    exploit vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2614)

  - Vulnerability in the MySQL Server component of Oracle MySQL (subcomponent: Server: Security: Privileges).
    Supported versions that are affected are 5.6.43 and prior, 5.7.25 and prior and 8.0.15 and prior. Easily
    exploitable vulnerability allows high privileged attacker with network access via multiple protocols to
    compromise MySQL Server. Successful attacks of this vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete DOS) of MySQL Server. (CVE-2019-2627)

  - An out of bounds read flaw was discovered in libssh2 before 1.8.1 when a specially crafted SFTP packet is
    received from the server. A remote attacker who compromises a SSH server may be able to cause a Denial of
    Service or read data in the client memory. (CVE-2019-3858)

  - An out of bounds read flaw was discovered in libssh2 before 1.8.1 in the way SSH packets with a padding
    length value greater than the packet length are parsed. A remote attacker who compromises a SSH server may
    be able to cause a Denial of Service or read data in the client memory. (CVE-2019-3861)

  - An exploitable denial-of-service vulnerability exists in the X509 certificate parser of Python.org Python
    2.7.11 / 3.6.6. A specially crafted X509 certificate can cause a NULL pointer dereference, resulting in a
    denial of service. An attacker can initiate or accept TLS connections using crafted certificates to
    trigger this vulnerability. (CVE-2019-5010)

  - There had existed in one of the ISC BIND libraries a bug in a function that was used by dhcpd when
    operating in DHCPv6 mode. There was also a bug in dhcpd relating to the use of this function per its
    documentation, but the bug in the library function prevented this from causing any harm. All releases of
    dhcpd from ISC contain copies of this, and other, BIND libraries in combinations that have been tested
    prior to release and are known to not present issues like this. Some third-party packagers of ISC software
    have modified the dhcpd source, BIND source, or version matchup in ways that create the crash potential.
    Based on reports available to ISC, the crash probability is large and no analysis has been done on how, or
    even if, the probability can be manipulated by an attacker. Affects: Builds of dhcpd versions prior to
    version 4.4.1 when using BIND versions 9.11.2 or later, or BIND versions with specific bug fixes
    backported to them. ISC does not have access to comprehensive version lists for all repackagings of dhcpd
    that are vulnerable. In particular, builds from other vendors may also be affected. Operators are advised
    to consult their vendor documentation. (CVE-2019-6470)

  - A heap-based buffer over-read was discovered in the function read_srclines in dwarf_getsrclines.c in libdw
    in elfutils 0.175. A crafted input can cause segmentation faults, leading to denial-of-service, as
    demonstrated by eu-nm. (CVE-2019-7149)

  - An issue was discovered in elfutils 0.175. A segmentation fault can occur in the function elf64_xlatetom
    in libelf/elf32_xlatetom.c, due to dwfl_segment_report_module not checking whether the dyn data read from
    a core file is truncated. A crafted input can cause a program crash, leading to denial-of-service, as
    demonstrated by eu-stack. (CVE-2019-7150)

  - In elfutils 0.175, a negative-sized memcpy is attempted in elf_cvt_note in libelf/note_xlate.h because of
    an incorrect overflow check. Crafted elf input causes a segmentation fault, leading to denial of service
    (program crash). (CVE-2019-7664)

  - In elfutils 0.175, a heap-based buffer over-read was discovered in the function elf32_xlatetom in
    elf32_xlatetom.c in libelf. A crafted ELF input can cause a segmentation fault leading to denial of
    service (program crash) because ebl_core_note does not reject malformed core file notes. (CVE-2019-7665)

  - An issue was discovered in urllib2 in Python 2.x through 2.7.16 and urllib in Python 3.x through 3.7.3.
    CRLF injection is possible if the attacker controls a url parameter, as demonstrated by the first argument
    to urllib.request.urlopen with \r
 (specifically in the query string after a ? character) followed by an
    HTTP header or a Redis command. This is fixed in: v2.7.17, v2.7.17rc1, v2.7.18, v2.7.18rc1; v3.5.10,
    v3.5.10rc1, v3.5.8, v3.5.8rc1, v3.5.8rc2, v3.5.9; v3.6.10, v3.6.10rc1, v3.6.11, v3.6.11rc1, v3.6.12,
    v3.6.9, v3.6.9rc1; v3.7.4, v3.7.4rc1, v3.7.4rc2, v3.7.5, v3.7.5rc1, v3.7.6, v3.7.6rc1, v3.7.7, v3.7.7rc1,
    v3.7.8, v3.7.8rc1, v3.7.9. (CVE-2019-9740)

  - An issue was discovered in urllib2 in Python 2.x through 2.7.16 and urllib in Python 3.x through 3.7.3.
    CRLF injection is possible if the attacker controls a url parameter, as demonstrated by the first argument
    to urllib.request.urlopen with \r
 (specifically in the path component of a URL that lacks a ? character)
    followed by an HTTP header or a Redis command. This is similar to the CVE-2019-9740 query string issue.
    This is fixed in: v2.7.17, v2.7.17rc1, v2.7.18, v2.7.18rc1; v3.5.10, v3.5.10rc1, v3.5.8, v3.5.8rc1,
    v3.5.8rc2, v3.5.9; v3.6.10, v3.6.10rc1, v3.6.11, v3.6.11rc1, v3.6.12, v3.6.9, v3.6.9rc1; v3.7.4,
    v3.7.4rc1, v3.7.4rc2, v3.7.5, v3.7.5rc1, v3.7.6, v3.7.6rc1, v3.7.7, v3.7.7rc1, v3.7.8, v3.7.8rc1, v3.7.9.
    (CVE-2019-9947)

  - urllib in Python 2.x through 2.7.16 supports the local_file: scheme, which makes it easier for remote
    attackers to bypass protection mechanisms that blacklist file: URIs, as demonstrated by triggering a
    urllib.urlopen('local_file:///etc/passwd') call. (CVE-2019-9948)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?afbb91ae");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14618");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1010238");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/21");
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
  { 'fixed_version' : '5.16', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.16 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.16', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.16 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
