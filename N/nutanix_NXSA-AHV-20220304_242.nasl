#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170564);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/23");

  script_cve_id(
    "CVE-2018-25032",
    "CVE-2020-25709",
    "CVE-2020-25710",
    "CVE-2020-26116",
    "CVE-2020-26137",
    "CVE-2021-3177",
    "CVE-2021-4034",
    "CVE-2021-21996",
    "CVE-2021-42574",
    "CVE-2021-45417",
    "CVE-2021-45960",
    "CVE-2021-46143",
    "CVE-2022-0778",
    "CVE-2022-1271",
    "CVE-2022-2526",
    "CVE-2022-22822",
    "CVE-2022-22823",
    "CVE-2022-22824",
    "CVE-2022-22825",
    "CVE-2022-22826",
    "CVE-2022-22827",
    "CVE-2022-23852",
    "CVE-2022-24407",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25315",
    "CVE-2022-29154"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/18");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20220304.242)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20220304.242. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20220304.242 advisory.

  - zlib before 1.2.12 allows memory corruption when deflating (i.e., when compressing) if the input has many
    distant matches. (CVE-2018-25032)

  - A flaw was found in OpenLDAP. This flaw allows an attacker who can send a malicious packet to be processed
    by OpenLDAP's slapd server, to trigger an assertion failure. The highest threat from this vulnerability is
    to system availability. (CVE-2020-25709)

  - A flaw was found in OpenLDAP in versions before 2.4.56. This flaw allows an attacker who sends a malicious
    packet processed by OpenLDAP to force a failed assertion in csnNormalize23(). The highest threat from this
    vulnerability is to system availability. (CVE-2020-25710)

  - http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5
    allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR
    and LF control characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

  - urllib3 before 1.25.9 allows CRLF injection if the attacker controls the HTTP request method, as
    demonstrated by inserting CR and LF control characters in the first argument of putrequest(). NOTE: this
    is similar to CVE-2020-26116. (CVE-2020-26137)

  - An issue was discovered in SaltStack Salt before 3003.3. A user who has control of the source, and
    source_hash URLs can gain full file system access as root on a salt minion. (CVE-2021-21996)

  - Python 3.x through 3.9.1 has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may lead to
    remote code execution in certain Python applications that accept floating-point numbers as untrusted
    input, as demonstrated by a 1e300 argument to c_double.from_param. This occurs because sprintf is used
    unsafely. (CVE-2021-3177)

  - A local privilege escalation vulnerability was found on polkit's pkexec utility. The pkexec application is
    a setuid tool designed to allow unprivileged users to run commands as privileged users according
    predefined policies. The current version of pkexec doesn't handle the calling parameters count correctly
    and ends trying to execute environment variables as commands. An attacker can leverage this by crafting
    environment variables in such a way it'll induce pkexec to execute arbitrary code. When successfully
    executed the attack can cause a local privilege escalation given unprivileged users administrative rights
    on the target machine. (CVE-2021-4034)

  - ** DISPUTED ** An issue was discovered in the Bidirectional Algorithm in the Unicode Specification through
    14.0. It permits the visual reordering of characters via control sequences, which can be used to craft
    source code that renders different logic than the logical ordering of tokens ingested by compilers and
    interpreters. Adversaries can leverage this to encode source code for compilers accepting Unicode such
    that targeted vulnerabilities are introduced invisibly to human reviewers. NOTE: the Unicode Consortium
    offers the following alternative approach to presenting this concern. An issue is noted in the nature of
    international text that can affect applications that implement support for The Unicode Standard and the
    Unicode Bidirectional Algorithm (all versions). Due to text display behavior when text includes left-to-
    right and right-to-left characters, the visual order of tokens may be different from their logical order.
    Additionally, control characters needed to fully support the requirements of bidirectional text can
    further obfuscate the logical order of tokens. Unless mitigated, an adversary could craft source code such
    that the ordering of tokens perceived by human reviewers does not match what will be processed by a
    compiler/interpreter/etc. The Unicode Consortium has documented this class of vulnerability in its
    document, Unicode Technical Report #36, Unicode Security Considerations. The Unicode Consortium also
    provides guidance on mitigations for this class of issues in Unicode Technical Standard #39, Unicode
    Security Mechanisms, and in Unicode Standard Annex #31, Unicode Identifier and Pattern Syntax. Also, the
    BIDI specification allows applications to tailor the implementation in ways that can mitigate misleading
    visual reordering in program text; see HL4 in Unicode Standard Annex #9, Unicode Bidirectional Algorithm.
    (CVE-2021-42574)

  - AIDE before 0.17.4 allows local users to obtain root privileges via crafted file metadata (such as XFS
    extended attributes or tmpfs ACLs), because of a heap-based buffer overflow. (CVE-2021-45417)

  - In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in
    xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).
    (CVE-2021-45960)

  - In doProlog in xmlparse.c in Expat (aka libexpat) before 2.4.3, an integer overflow exists for
    m_groupSize. (CVE-2021-46143)

  - The BN_mod_sqrt() function, which computes a modular square root, contains a bug that can cause it to loop
    forever for non-prime moduli. Internally this function is used when parsing certificates that contain
    elliptic curve public keys in compressed form or explicit elliptic curve parameters with a base point
    encoded in compressed form. It is possible to trigger the infinite loop by crafting a certificate that has
    invalid explicit curve parameters. Since certificate parsing happens prior to verification of the
    certificate signature, any process that parses an externally supplied certificate may thus be subject to a
    denial of service attack. The infinite loop can also be reached when parsing crafted private keys as they
    can contain explicit elliptic curve parameters. Thus vulnerable situations include: - TLS clients
    consuming server certificates - TLS servers consuming client certificates - Hosting providers taking
    certificates or private keys from customers - Certificate authorities parsing certification requests from
    subscribers - Anything else which parses ASN.1 elliptic curve parameters Also any other applications that
    use the BN_mod_sqrt() where the attacker can control the parameter values are vulnerable to this DoS
    issue. In the OpenSSL 1.0.2 version the public key is not parsed during initial parsing of the certificate
    which makes it slightly harder to trigger the infinite loop. However any operation which requires the
    public key from the certificate will trigger the infinite loop. In particular the attacker can use a self-
    signed certificate to trigger the loop during verification of the certificate signature. This issue
    affects OpenSSL versions 1.0.2, 1.1.1 and 3.0. It was addressed in the releases of 1.1.1n and 3.0.2 on the
    15th March 2022. Fixed in OpenSSL 3.0.2 (Affected 3.0.0,3.0.1). Fixed in OpenSSL 1.1.1n (Affected
    1.1.1-1.1.1m). Fixed in OpenSSL 1.0.2zd (Affected 1.0.2-1.0.2zc). (CVE-2022-0778)

  - An arbitrary file write vulnerability was found in GNU gzip's zgrep utility. When zgrep is applied on the
    attacker's chosen file name (for example, a crafted file name), this can overwrite an attacker's content
    to an arbitrary attacker-selected file. This flaw occurs due to insufficient validation when processing
    filenames with two or more newlines where selected content and the target file names are embedded in
    crafted multi-line file names. This flaw allows a remote, low privileged attacker to force zgrep to write
    arbitrary files on the system. (CVE-2022-1271)

  - addBinding in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22822)

  - build_model in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22823)

  - defineAttribute in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22824)

  - lookup in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22825)

  - nextScaffoldPart in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow.
    (CVE-2022-22826)

  - storeAtts in xmlparse.c in Expat (aka libexpat) before 2.4.3 has an integer overflow. (CVE-2022-22827)

  - Expat (aka libexpat) before 2.4.4 has a signed integer overflow in XML_GetBuffer, for configurations with
    a nonzero XML_CONTEXT_BYTES. (CVE-2022-23852)

  - In Cyrus SASL 2.1.17 through 2.1.27 before 2.1.28, plugins/sql.c does not escape the password for a SQL
    INSERT or UPDATE statement. (CVE-2022-24407)

  - xmltok_impl.c in Expat (aka libexpat) before 2.4.5 lacks certain validation of encoding, such as checks
    for whether a UTF-8 character is valid in a certain context. (CVE-2022-25235)

  - xmlparse.c in Expat (aka libexpat) before 2.4.5 allows attackers to insert namespace-separator characters
    into namespace URIs. (CVE-2022-25236)

  - A use-after-free vulnerability was found in systemd. This issue occurs due to the on_stream_io() function
    and dns_stream_complete() function in 'resolved-dns-stream.c' not incrementing the reference counting for
    the DnsStream object. Therefore, other functions and callbacks called can dereference the DNSStream
    object, causing the use-after-free when the reference is still used later. (CVE-2022-2526)

  - In Expat (aka libexpat) before 2.4.5, there is an integer overflow in storeRawNames. (CVE-2022-25315)

  - An issue was discovered in rsync before 3.2.5 that allows malicious remote servers to write arbitrary
    files inside the directories of connecting peers. The server chooses which files/directories are sent to
    the client. However, the rsync client performs insufficient validation of file names. A malicious rsync
    server (or Man-in-The-Middle attacker) can overwrite arbitrary files in the rsync client target directory
    and subdirectories (for example, overwrite the .ssh/authorized_keys file). (CVE-2022-29154)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20220304.242
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4f88613");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to recommended version.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45960");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-25315");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Local Privilege Escalation in polkits pkexec');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20220304.242', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20220304.242 or higher.' }
];

vcf::nutanix::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
