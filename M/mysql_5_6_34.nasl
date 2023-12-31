#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94166);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/14");

  script_cve_id(
    "CVE-2016-2177",
    "CVE-2016-2178",
    "CVE-2016-2179",
    "CVE-2016-2180",
    "CVE-2016-2181",
    "CVE-2016-2182",
    "CVE-2016-2183",
    "CVE-2016-3492",
    "CVE-2016-5584",
    "CVE-2016-5616",
    "CVE-2016-5617",
    "CVE-2016-5626",
    "CVE-2016-5629",
    "CVE-2016-6302",
    "CVE-2016-6303",
    "CVE-2016-6304",
    "CVE-2016-6306",
    "CVE-2016-6662",
    "CVE-2016-7440",
    "CVE-2016-8283"
  );
  script_bugtraq_id(
    91081,
    91319,
    92117,
    92557,
    92628,
    92630,
    92912,
    92982,
    92984,
    92987,
    93150,
    93153,
    93612,
    93614,
    93638,
    93650,
    93659,
    93668,
    93735,
    93737
  );
  script_xref(name:"EDB-ID", value:"40360");

  script_name(english:"MySQL 5.6.x < 5.6.34 Multiple Vulnerabilities (October 2016 CPU) (SWEET32)");
  script_summary(english:"Checks the version of MySQL server.");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of MySQL running on the remote host is 5.6.x prior to
5.6.34. It is, therefore, affected by multiple vulnerabilities :

  - Multiple integer overflow conditions exist in s3_srvr.c,
    ssl_sess.c, and t1_lib.c due to improper use of pointer
    arithmetic for heap-buffer boundary checks. An
    unauthenticated, remote attacker can exploit this to
    cause a denial of service. (CVE-2016-2177)

  - An information disclosure vulnerability exists in the
    dsa_sign_setup() function in dsa_ossl.c due to a failure
    to properly ensure the use of constant-time operations.
    An unauthenticated, remote attacker can exploit this,
    via a timing side-channel attack, to disclose DSA key
    information. (CVE-2016-2178)

  - A denial of service vulnerability exists in the DTLS
    implementation due to a failure to properly restrict the
    lifetime of queue entries associated with unused
    out-of-order messages. An unauthenticated, remote
    attacker can exploit this, by maintaining multiple
    crafted DTLS sessions simultaneously, to exhaust memory.
    (CVE-2016-2179)

  - An out-of-bounds read error exists in the X.509 Public
    Key Infrastructure Time-Stamp Protocol (TSP)
    implementation. An unauthenticated, remote attacker can
    exploit this, via a crafted time-stamp file that is
    mishandled by the 'openssl ts' command, to cause
    denial of service or to disclose sensitive information.
    (CVE-2016-2180)

  - A denial of service vulnerability exists in the
    Anti-Replay feature in the DTLS implementation due to
    improper handling of epoch sequence numbers in records.
    An unauthenticated, remote attacker can exploit this,
    via spoofed DTLS records, to cause legitimate packets to
    be dropped. (CVE-2016-2181)

  - An overflow condition exists in the BN_bn2dec() function
    in bn_print.c due to improper validation of
    user-supplied input when handling BIGNUM values. An
    unauthenticated, remote attacker can exploit this to
    crash the process. (CVE-2016-2182)

  - A vulnerability exists, known as SWEET32, in the 3DES
    and Blowfish algorithms due to the use of weak 64-bit
    block ciphers by default. A man-in-the-middle attacker
    who has sufficient resources can exploit this
    vulnerability, via a 'birthday' attack, to detect a
    collision that leaks the XOR between the fixed secret
    and a known plaintext, allowing the disclosure of the
    secret text, such as secure HTTPS cookies, and possibly
    resulting in the hijacking of an authenticated session.
    (CVE-2016-2183)

  - An unspecified flaw exists in the Optimizer subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-3492)

  - An unspecified flaw exists in the Security: Encryption
    subcomponent that allows an authenticated, remote
    attacker to disclose sensitive information.
    (CVE-2016-5584)

  - An unspecified flaw exists in the MyISAM subcomponent
    that allows a local attacker to gain elevated
    privileges. (CVE-2016-5616)

  - An unspecified flaw exists in the Error Handling
    subcomponent that allows a local attacker to gain
    elevated privileges. (CVE-2016-5617)

  - An unspecified flaw exists in the GIS subcomponent that
    allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5626)

  - An unspecified flaw exists in the Federated subcomponent
    that allows an authenticated, remote attacker to cause a
    denial of service condition. (CVE-2016-5629)

  - A flaw exists in the tls_decrypt_ticket() function in
    t1_lib.c due to improper handling of ticket HMAC
    digests. An unauthenticated, remote attacker can exploit
    this, via a ticket that is too short, to crash the
    process, resulting in a denial of service.
    (CVE-2016-6302)

  - An integer overflow condition exists in the
    MDC2_Update() function in mdc2dgst.c due to improper
    validation of user-supplied input. An unauthenticated,
    remote attacker can exploit this to cause a heap-based
    buffer overflow, resulting in a denial of service
    condition or possibly the execution of arbitrary code.
    (CVE-2016-6303)

  - A flaw exists in the ssl_parse_clienthello_tlsext()
    function in t1_lib.c due to improper handling of overly
    large OCSP Status Request extensions from clients. An
    unauthenticated, remote attacker can exploit this, via
    large OCSP Status Request extensions, to exhaust memory
    resources, resulting in a denial of service condition.
    (CVE-2016-6304)

  - An out-of-bounds read error exists in the certificate
    parser that allows an unauthenticated, remote attacker
    to cause a denial of service via crafted certificate
    operations. (CVE-2016-6306)

  - A flaw exists in the check_log_path() function within
    file sql/sys_vars.cc due to inadequate restrictions on
    the ability to write to the my.cnf configuration file
    and allowing the loading of configuration files from
    path locations not used by current versions. An
    authenticated, remote attacker can exploit this issue
    by using specially crafted queries that utilize logging
    functionality to create new files or append custom
    content to existing files. This allows the attacker to
    gain root privileges by inserting a custom .cnf file
    with a 'malloc_lib=' directive pointing to specially
    crafted mysql_hookandroot_lib.so file and thereby cause
    MySQL to load a malicious library the next time it is
    started. (CVE-2016-6662)

  - A flaw exists in wolfSSL, specifically within the C
    software version of AES Encryption and Decryption, due
    to table lookups not properly considering cache-bank
    access times. A local attacker can exploit this, via a
    specially crafted application, to disclose AES keys.
    (CVE-2016-7440)

  - An unspecified flaw exists in the Types subcomponent
    that allows an authenticated, remote attacker to cause
    a denial of service condition.(CVE-2016-8283)");
  # http://www.oracle.com/technetwork/security-advisory/cpuoct2016-2881722.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bac902d5");
  script_set_attribute(attribute:"see_also", value:"https://dev.mysql.com/doc/relnotes/mysql/5.6/en/news-5-6-34.html");
  # http://legalhackers.com/advisories/MySQL-Exploit-Remote-Root-Code-Execution-Privesc-CVE-2016-6662.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fbd97f45");
  script_set_attribute(attribute:"see_also", value:"https://sweet32.info/");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/blog/blog/2016/08/24/sweet32/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to MySQL version 5.6.34 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-6662");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:mysql");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mysql_version.nasl", "mysql_login.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}

include("mysql_version.inc");

mysql_check_version(fixed:'5.6.34', min:'5.6', severity:SECURITY_HOLE);
