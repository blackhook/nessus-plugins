#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(101845);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6305",
    "CVE-2016-6306",
    "CVE-2016-6307",
    "CVE-2016-6308",
    "CVE-2016-6309",
    "CVE-2016-7052",
    "CVE-2017-3562",
    "CVE-2017-10112",
    "CVE-2017-10113",
    "CVE-2017-10130",
    "CVE-2017-10143",
    "CVE-2017-10144",
    "CVE-2017-10170",
    "CVE-2017-10171",
    "CVE-2017-10174",
    "CVE-2017-10175",
    "CVE-2017-10177",
    "CVE-2017-10179",
    "CVE-2017-10180",
    "CVE-2017-10184",
    "CVE-2017-10185",
    "CVE-2017-10186",
    "CVE-2017-10191",
    "CVE-2017-10192",
    "CVE-2017-10244",
    "CVE-2017-10245",
    "CVE-2017-10246"
  );
  script_bugtraq_id(
    91081,
    91319,
    92117,
    92557,
    92628,
    92630,
    92982,
    92984,
    92987,
    93149,
    93150,
    93151,
    93152,
    93153,
    93171,
    93177,
    99625,
    99630,
    99633,
    99636,
    99639,
    99647,
    99655,
    99658,
    99663,
    99664,
    99672,
    99678,
    99685,
    99690,
    99693,
    99700,
    99702,
    99708,
    99713,
    99715,
    99717
  );

  script_name(english:"Oracle E-Business Multiple Vulnerabilities (July 2017 CPU) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"A web application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Oracle E-Business installed on the remote host is
missing the July 2017 Oracle Critical Patch Update (CPU). It is,
therefore, affected by the following vulnerabilities :

  - Multiple integer overflow conditions exist in the
    OpenSSL component in s3_srvr.c, ssl_sess.c, and t1_lib.c
    due to improper use of pointer arithmetic for
    heap-buffer boundary checks. An unauthenticated, remote
    attacker can exploit this to cause a denial of service.
    (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    OpenSSL component in the dsa_sign_setup() function in
    dsa_ossl.c due to a failure to properly ensure the use
    of constant-time operations. An unauthenticated, remote
    attacker can exploit this, via a timing side-channel
    attack, to disclose DSA key information. (CVE-2016-2178)

  - A denial of service vulnerability exists in the OpennSSL
    component in the DTLS implementation due to a failure to
    properly restrict the lifetime of queue entries
    associated with unused out-of-order messages. An
    unauthenticated, remote attacker can exploit this, by
    maintaining multiple crafted DTLS sessions
    simultaneously, to exhaust memory. (CVE-2016-2179)

  - An out-of-bounds read error exists in the OpenSSL
    component in the X.509 Public Key Infrastructure
    Time-Stamp Protocol (TSP) implementation. An
    unauthenticated, remote attacker can exploit this, via a
    crafted time-stamp file that is mishandled by the
    'openssl ts' command, to cause a denial of service or to
    disclose sensitive information. (CVE-2016-2180)

  - A denial of service vulnerability exists in the OpenSSL
    component in the Anti-Replay feature in the DTLS
    implementation due to improper handling of epoch
    sequence numbers in records. An unauthenticated, remote
    attacker can exploit this, via spoofed DTLS records, to
    cause legitimate packets to be dropped. (CVE-2016-2181)

  - An overflow condition exists in the OpenSSL component in
    the BN_bn2dec() function in bn_print.c due to improper
    validation of user-supplied input when handling BIGNUM
    values. An unauthenticated, remote attacker can exploit
    this to crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the OpenSSL
    component in the 3DES and Blowfish algorithms due to the
    use of weak 64-bit block ciphers by default. A
    man-in-the-middle attacker who has sufficient resources
    can exploit this vulnerability, via a 'birthday' attack,
    to detect a collision that leaks the XOR between the
    fixed secret and a known plaintext, allowing the
    disclosure of the secret text, such as secure HTTPS
    cookies, and possibly resulting in the hijacking of an
    authenticated session. (CVE-2016-2183)

  - A flaw exists in the OpenSSL component in the
    tls_decrypt_ticket() function in t1_lib.c due to
    improper handling of ticket HMAC digests. An
    unauthenticated, remote attacker can exploit this, via a
    ticket that is too short, to crash the process,
    resulting in a denial of service. (CVE-2016-6302)

  - An integer overflow condition exists in the OpenSSL
    component in the MDC2_Update() function in mdc2dgst.c
    due to improper validation of user-supplied input. An
    unauthenticated, remote attacker can exploit this to
    cause a heap-based buffer overflow, resulting in a
    denial of service condition or possibly the execution of
    arbitrary code. (CVE-2016-6303)

  - A flaw exists in the OpenSSL component in the
    ssl_parse_clienthello_tlsext() function in t1_lib.c due
    to improper handling of overly large OCSP Status Request
    extensions from clients. An unauthenticated, remote
    attacker can exploit this, via large OCSP Status Request
    extensions, to exhaust memory resources, resulting in a
    denial of service condition. (CVE-2016-6304)

  - A flaw exists in the OpenSSL component in the SSL_peek()
    function in rec_layer_s3.c due to improper handling of
    empty records. An unauthenticated, remote attacker can
    exploit this, by triggering a zero-length record in an
    SSL_peek call, to cause an infinite loop, resulting in a
    denial of service condition. (CVE-2016-6305)

  - An out-of-bounds read error exists in the OpenSSL
    component in the certificate parser that allows an
    unauthenticated, remote attacker to cause a denial of
    service via crafted certificate operations.
    (CVE-2016-6306)

  - A denial of service vulnerability exists in the OpenSSL
    component in the state-machine implementation due to a
    failure to check for an excessive length before
    allocating memory. An unauthenticated, remote attacker
    can exploit this, via a crafted TLS message, to exhaust
    memory resources. (CVE-2016-6307)

  - A denial of service vulnerability exists in the OpenSSL
    component in the DTLS implementation due to improper
    handling of excessively long DTLS messages. An
    unauthenticated, remote attacker can exploit this, via a
    crafted DTLS message, to exhaust available memory
    resources. (CVE-2016-6308)

  - A remote code execution vulnerability exists in the
    OpenSSL component in the read_state_machine() function
    in statem.c due to improper handling of messages larger
    than 16k. An unauthenticated, remote attacker can
    exploit this, via a specially crafted message, to cause
    a use-after-free error, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6309)

  - A denial of service vulnerability exists in the OpenSSL
    component in x509_vfy.c due to improper handling of
    certificate revocation lists (CRLs). An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted CRL, to cause a NULL pointer dereference,
    resulting in a crash of the service. (CVE-2016-7052)

  - An unspecified flaw exists in the AD Utilities component
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-3562)

  - An unspecified flaw exists in the Registration component
    that allows an unauthenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2017-10112)

  - An unspecified flaw exists in the CRM User Management
    Framework component that allows an unauthenticated,
    remote attacker to impact confidentiality and integrity.
    (CVE-2017-10113)

  - An unspecified flaw exists in the User Management
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2017-10130)

  - An unspecified flaw exists in the Preferences component
    that allows an unauthenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2017-10143)

  - An unspecified flaw exists in the Oracle Diagnostics
    component that allows an unauthenticated, remote
    attacker to cause a denial of service condition.
    (CVE-2017-10144)

  - An unspecified flaw exists in the Wireless/WAP component
    that allows an unauthenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2017-10170)

  - An unspecified flaw exists in the Home Page component
    that allows an unauthenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2017-10171)

  - An unspecified flaw exists in the Service Request
    component that allows an unauthenticated, remote
    attacker to impact confidentiality and integrity.
    (CVE-2017-10174)

  - An unspecified flaw exists in the Profiles component
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10175)

  - An unspecified flaw exists in the Flexfields component
    that allows an authenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10177)

  - An unspecified flaw exists in the Monitoring component
    that allows an unauthenticated, remote attacker to
    impact confidentiality and integrity. (CVE-2017-10179)

  - A cross-site scripting (XSS) vulnerability exists in the
    CMRO component due to improper validation of
    user-supplied input to multiple parameters before
    returning it to users. An unauthenticated, remote
    attacker can exploit this, via a specially crafted
    request, to execute arbitrary script code in a user's
    browser session. (CVE-2017-10180)

  - An information disclosure vulnerability exists in the
    Wireless/WAP component due to improper sanitization of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a directory traversal attack, to
    disclose arbitrary files. (CVE-2017-10184)

  - A cross-site scripting (XSS) vulnerability exists in the
    User Management component due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-10185)

  - An information disclosure vulnerability exists in the
    User and Company Profile component due to improper
    sanitization of user-supplied input. An unauthenticated,
    remote attacker can exploit this, via a directory
    traversal attack, to disclose arbitrary files.
    (CVE-2017-10186)

  - A cross-site scripting (XSS) vulnerability exists in the
    Web Analytics component due to improper validation of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a specially crafted request, to
    execute arbitrary script code in a user's browser
    session. (CVE-2017-10191)

  - An information disclosure vulnerability exists in the
    Shopping Cart component due to improper sanitization of
    user-supplied input. An unauthenticated, remote attacker
    can exploit this, via a directory traversal attack, to
    disclose arbitrary files. (CVE-2017-10192)

  - An information disclosure vulnerability exists in the
    Attachments component that allows an unauthenticated,
    remote attacker to disclose any document stored on the
    system. (CVE-2017-10244)

  - An information disclosure vulnerability exists in the
    Account Hierarchy Manager component that allows an
    unauthenticated, remote attacker to disclose sensitive
    information in the DBC configuration file.
    (CVE-2017-10245)

  - An unspecified flaw exists in the iHelp component that
    allows an unauthenticated, remote attacker to impact
    confidentiality and integrity. (CVE-2017-10246)");
  # https://www.oracle.com/technetwork/security-advisory/cpujul2017-3236622.html#AppendixEBS
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f6b5a59");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the July 2017 Oracle Critical
Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6309");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:e-business_suite");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 Tenable Network Security, Inc.");

  script_dependencies("oracle_e-business_query_patch_info.nbin");
  script_require_keys("Oracle/E-Business/Version", "Oracle/E-Business/patches/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Oracle/E-Business/Version");
patches = get_kb_item_or_exit("Oracle/E-Business/patches/installed");

# Batch checks
if (patches) patches = split(patches, sep:',', keep:FALSE);
else patches = make_list();

p12_1 = '25982921';
p12_2 = '25982922';

# Check if the installed version is an affected version
affected_versions = make_array(
  '12.1.1', make_list(p12_1),
  '12.1.2', make_list(p12_1),
  '12.1.3', make_list(p12_1),

  '12.2.3', make_list(p12_2),
  '12.2.4', make_list(p12_2),
  '12.2.5', make_list(p12_2),
  '12.2.6', make_list(p12_2)
);

patched = FALSE;
affectedver = FALSE;

if (affected_versions[version])
{
  affectedver = TRUE;
  patchids = affected_versions[version];
  foreach required_patch (patchids)
  {
    foreach applied_patch (patches)
    {
      if(required_patch == applied_patch)
      {
        patched = applied_patch;
        break;
      }
    }
    if(patched) break;
  }
  if(!patched) patchreport = join(patchids,sep:" or ");
}

if (!patched && affectedver)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
  if(report_verbosity > 0)
  {
    report =
      '\n  Installed version : '+version+
      '\n  Fixed version     : '+version+' Patch '+patchreport+
      '\n';
    security_hole(port:0,extra:report);
  }
  else security_hole(0);
  exit(0);
}
else if (!affectedver) audit(AUDIT_INST_VER_NOT_VULN, 'Oracle E-Business', version);
else exit(0, 'The Oracle E-Business server ' + version + ' is not affected because patch ' + patched + ' has been applied.');
