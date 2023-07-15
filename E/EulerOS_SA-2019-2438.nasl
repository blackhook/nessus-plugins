#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131592);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2011-4718",
    "CVE-2014-9767",
    "CVE-2014-9912",
    "CVE-2015-5589",
    "CVE-2015-6831",
    "CVE-2015-6832",
    "CVE-2015-6833",
    "CVE-2015-7803",
    "CVE-2015-7804",
    "CVE-2015-8382",
    "CVE-2015-8835",
    "CVE-2015-8867",
    "CVE-2015-8874",
    "CVE-2015-8879",
    "CVE-2015-8935",
    "CVE-2016-10397",
    "CVE-2016-2554",
    "CVE-2016-3141",
    "CVE-2016-3142",
    "CVE-2016-3185",
    "CVE-2016-4070",
    "CVE-2016-4539",
    "CVE-2016-4540",
    "CVE-2016-4541",
    "CVE-2016-4542",
    "CVE-2016-4543",
    "CVE-2016-5093",
    "CVE-2016-5094",
    "CVE-2016-6288",
    "CVE-2016-6291",
    "CVE-2016-6292",
    "CVE-2016-6293",
    "CVE-2016-6294",
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7128",
    "CVE-2016-7411",
    "CVE-2016-7412",
    "CVE-2016-7414",
    "CVE-2016-7418",
    "CVE-2016-7480",
    "CVE-2016-9934",
    "CVE-2016-9935",
    "CVE-2017-11143",
    "CVE-2017-11144",
    "CVE-2017-11147",
    "CVE-2017-11628",
    "CVE-2017-12933",
    "CVE-2017-16642",
    "CVE-2017-7272",
    "CVE-2017-9224",
    "CVE-2017-9226",
    "CVE-2017-9227",
    "CVE-2017-9228",
    "CVE-2017-9229",
    "CVE-2018-10545",
    "CVE-2018-10547",
    "CVE-2018-14851",
    "CVE-2018-17082",
    "CVE-2018-5712",
    "CVE-2019-11040",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11043"
  );
  script_bugtraq_id(61929, 75974);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"EulerOS 2.0 SP2 : php (EulerOS-SA-2019-2438)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24
    and 7.3.x below 7.3.11 in certain configurations of FPM
    setup it is possible to cause FPM module to write past
    allocated buffers into the space reserved for FCGI
    protocol data, thus opening the possibility of remote
    code execution.(CVE-2019-11043)

  - The finish_nested_data function in
    ext/standard/var_unserializer.re in PHP before 5.6.31,
    7.0.x before 7.0.21, and 7.1.x before 7.1.7 is prone to
    a buffer over-read while unserializing untrusted data.
    Exploitation of this issue can have an unspecified
    impact on the integrity of PHP.(CVE-2017-12933)

  - ext/standard/var_unserializer.c in PHP before 5.6.25
    and 7.x before 7.0.10 mishandles certain invalid
    objects, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via crafted serialized data that leads to a (1)
    __destruct call or (2) magic method
    call.(CVE-2016-7124)

  - The match function in pcre_exec.c in PCRE before 8.37
    mishandles the
    /(?:((abcd))|(((?:(?:(?:(?:abc|(?:abcdef))))b)abcdefghi
    )abc)|((*ACCEPT)))/ pattern and related patterns
    involving (*ACCEPT), which allows remote attackers to
    obtain sensitive information from process memory or
    cause a denial of service (partially initialized memory
    and application crash) via a crafted regular
    expression, as demonstrated by a JavaScript RegExp
    object encountered by Konqueror, aka
    ZDI-CAN-2547.(CVE-2015-8382)

  - An issue was discovered in PHP before 5.6.33, 7.0.x
    before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before
    7.2.1. There is Reflected XSS on the PHAR 404 error
    page via the URI of a request for a .phar
    file.(CVE-2018-5712)

  - exif_process_IFD_in_MAKERNOTE in ext/exif/exif.c in PHP
    before 5.6.37, 7.0.x before 7.0.31, 7.1.x before
    7.1.20, and 7.2.x before 7.2.8 allows remote attackers
    to cause a denial of service (out-of-bounds read and
    application crash) via a crafted JPEG
    file.(CVE-2018-14851)

  - The SplObjectStorage unserialize implementation in
    ext/spl/spl_observer.c in PHP before 7.0.12 does not
    verify that a key is an object, which allows remote
    attackers to execute arbitrary code or cause a denial
    of service (uninitialized memory access) via crafted
    serialized data.(CVE-2016-7480)

  - ext/standard/var_unserializer.re in PHP before 5.6.26
    mishandles object-deserialization failures, which
    allows remote attackers to cause a denial of service
    (memory corruption) or possibly have unspecified other
    impact via an unserialize call that references a
    partially constructed object.(CVE-2016-7411)

  - The odbc_bindcols function in ext/odbc/php_odbc.c in
    PHP before 5.6.12 mishandles driver behavior for
    SQL_WVARCHAR columns, which allows remote attackers to
    cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table.(CVE-2015-8879)

  - In PHP before 5.6.32, 7.x before 7.0.25, and 7.1.x
    before 7.1.11, an error in the date extension's
    timelib_meridian handling of 'front of' and 'back of'
    directives could be used by attackers able to supply
    date strings to leak information from the interpreter,
    related to ext/date/lib/parse_date.c out-of-bounds
    reads affecting the php_parse_date function. NOTE: this
    is a different issue than
    CVE-2017-11145.(CVE-2017-16642)

  - The exif_process_IFD_in_JPEG function in
    ext/exif/exif.c in PHP before 5.5.35, 5.6.x before
    5.6.21, and 7.x before 7.0.6 does not validate IFD
    sizes, which allows remote attackers to cause a denial
    of service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header
    data.(CVE-2016-4543)

  - The exif_process_IFD_TAG function in ext/exif/exif.c in
    PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 does not properly construct spprintf arguments,
    which allows remote attackers to cause a denial of
    service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header
    data.(CVE-2016-4542)

  - The grapheme_strpos function in
    ext/intl/grapheme/grapheme_string.c in PHP before
    5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6
    allows remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a negative offset.(CVE-2016-4541)

  - The grapheme_stripos function in
    ext/intl/grapheme/grapheme_string.c in PHP before
    5.5.35, 5.6.x before 5.6.21, and 7.x before 7.0.6
    allows remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a negative offset.(CVE-2016-4540)

  - The xml_parse_into_struct function in ext/xml/xml.c in
    PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 allows remote attackers to cause a denial of
    service (buffer under-read and segmentation fault) or
    possibly have unspecified other impact via crafted XML
    data in the second argument, leading to a parser level
    of zero.(CVE-2016-4539)

  - ** DISPUTED ** Integer overflow in the
    php_raw_url_encode function in ext/standard/url.c in
    PHP before 5.5.34, 5.6.x before 5.6.20, and 7.x before
    7.0.5 allows remote attackers to cause a denial of
    service (application crash) via a long string to the
    rawurlencode function. NOTE: the vendor says 'Not sure
    if this qualifies as security issue (probably
    not).'(CVE-2016-4070)

  - Use-after-free vulnerability in wddx.c in the WDDX
    extension in PHP before 5.5.33 and 5.6.x before 5.6.19
    allows remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    have unspecified other impact by triggering a
    wddx_deserialize call on XML data containing a crafted
    var element.(CVE-2016-3141)

  - In PHP before 5.6.28 and 7.x before 7.0.13, incorrect
    handling of various URI components in the URL parser
    could be used by attackers to bypass hostname-specific
    URL checks, as demonstrated by
    evil.example.com:80#@good.example.com/ and
    evil.example.com:80?@good.example.com/ inputs to the
    parse_url function (implemented in the php_url_parse_ex
    function in ext/standard/url.c).(CVE-2016-10397)

  - Multiple use-after-free vulnerabilities in SPL in PHP
    before 5.4.44, 5.5.x before 5.5.28, and 5.6.x before
    5.6.12 allow remote attackers to execute arbitrary code
    via vectors involving (1) ArrayObject, (2)
    SplObjectStorage, and (3) SplDoublyLinkedList, which
    are mishandled during unserialization.(CVE-2015-6831)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A heap out-of-bounds write occurs in
    bitset_set_range() during regular expression
    compilation due to an uninitialized variable from an
    incorrect state transition. An incorrect state
    transition in parse_char_class() could create an
    execution path that leaves a critical local variable
    uninitialized until it's used as an index, resulting in
    an out-of-bounds write memory
    corruption.(CVE-2017-9228)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A stack out-of-bounds read occurs in
    mbc_enc_len() during regular expression searching.
    Invalid handling of reg->dmin in forward_search_range()
    could result in an invalid pointer dereference, as an
    out-of-bounds read from a stack buffer.(CVE-2017-9227)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A heap out-of-bounds write or read
    occurs in next_state_val() during regular expression
    compilation. Octal numbers larger than 0xff are not
    handled correctly in fetch_token() and
    fetch_token_in_cc(). A malformed regular expression
    containing an octal number in the form of '\700' would
    produce an invalid code point value larger than 0xff in
    next_state_val(), resulting in an out-of-bounds write
    memory corruption.(CVE-2017-9226)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A stack out-of-bounds read occurs in
    match_at() during regular expression searching. A
    logical error involving order of validation and access
    in match_at() could result in an out-of-bounds read
    from a stack buffer.(CVE-2017-9224)

  - The exif_process_IFD_in_MAKERNOTE function in
    ext/exif/exif.c in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9 allows remote attackers to
    cause a denial of service (out-of-bounds array access
    and memory corruption), obtain sensitive information
    from process memory, or possibly have unspecified other
    impact via a crafted JPEG image.(CVE-2016-6291)

  - The php_url_parse_ex function in ext/standard/url.c in
    PHP before 5.5.38 allows remote attackers to cause a
    denial of service (buffer over-read) or possibly have
    unspecified other impact via vectors involving the
    smart_str data type.(CVE-2016-6288)

  - Integer overflow in the php_html_entities function in
    ext/standard/html.c in PHP before 5.5.36 and 5.6.x
    before 5.6.22 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact by
    triggering a large output string from the
    htmlspecialchars function.(CVE-2016-5094)

  - The get_icu_value_internal function in
    ext/intl/locale/locale_methods.c in PHP before 5.5.36,
    5.6.x before 5.6.22, and 7.x before 7.0.7 does not
    ensure the presence of a '\0' character, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a crafted locale_get_primary_language
    call.(CVE-2016-5093)

  - In PHP before 5.6.31, an invalid free in the WDDX
    deserialization of boolean parameters could be used by
    attackers able to inject XML for deserialization to
    crash the PHP interpreter, related to an invalid free
    for an empty boolean element in
    ext/wddx/wddx.c.(CVE-2017-11143)

  - The php_wddx_push_element function in ext/wddx/wddx.c
    in PHP before 5.6.29 and 7.x before 7.0.14 allows
    remote attackers to cause a denial of service
    (out-of-bounds read and memory corruption) or possibly
    have unspecified other impact via an empty boolean
    element in a wddxPacket XML document.(CVE-2016-9935)

  - ext/wddx/wddx.c in PHP before 5.6.28 and 7.x before
    7.0.13 allows remote attackers to cause a denial of
    service (NULL pointer dereference) via crafted
    serialized data in a wddxPacket XML document, as
    demonstrated by a PDORow string.(CVE-2016-9934)

  - The ZIP signature-verification feature in PHP before
    5.6.26 and 7.x before 7.0.11 does not ensure that the
    uncompressed_filesize field is large enough, which
    allows remote attackers to cause a denial of service
    (out-of-bounds memory access) or possibly have
    unspecified other impact via a crafted PHAR archive,
    related to ext/phar/util.c and
    ext/phar/zip.c.(CVE-2016-7414)

  - ext/mysqlnd/mysqlnd_wireprotocol.c in PHP before 5.6.26
    and 7.x before 7.0.11 does not verify that a BIT field
    has the UNSIGNED_FLAG flag, which allows remote MySQL
    servers to cause a denial of service (heap-based buffer
    overflow) or possibly have unspecified other impact via
    crafted field metadata.(CVE-2016-7412)

  - An issue was discovered in Oniguruma 6.2.0, as used in
    Oniguruma-mod in Ruby through 2.4.1 and mbstring in PHP
    through 7.1.5. A SIGSEGV occurs in
    left_adjust_char_head() during regular expression
    compilation. Invalid handling of reg->dmax in
    forward_search_range() could result in an invalid
    pointer dereference, normally as an immediate
    denial-of-service condition.(CVE-2017-9229)

  - The openssl_random_pseudo_bytes function in
    ext/openssl/openssl.c in PHP before 5.4.44, 5.5.x
    before 5.5.28, and 5.6.x before 5.6.12 incorrectly
    relies on the deprecated RAND_pseudo_bytes function,
    which makes it easier for remote attackers to defeat
    cryptographic protection mechanisms via unspecified
    vectors.(CVE-2015-8867)

  - The sapi_header_op function in main/SAPI.c in PHP
    before 5.4.38, 5.5.x before 5.5.22, and 5.6.x before
    5.6.6 supports deprecated line folding without
    considering browser compatibility, which allows remote
    attackers to conduct cross-site scripting (XSS) attacks
    against Internet Explorer by leveraging (1) %0A%20 or
    (2) %0D%0A%20 mishandling in the header
    function.(CVE-2015-8935)

  - An issue was discovered in PHP before 5.6.35, 7.0.x
    before 7.0.29, 7.1.x before 7.1.16, and 7.2.x before
    7.2.4. Dumpable FPM child processes allow bypassing
    opcache access controls because fpm_unix.c makes a
    PR_SET_DUMPABLE prctl call, allowing one user (in a
    multiuser environment) to obtain sensitive information
    from the process memory of a second user's PHP
    applications by running gcore on the PID of the PHP-FPM
    worker process.(CVE-2018-10545)

  - An issue was discovered in ext/phar/phar_object.c in
    PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before
    7.1.17, and 7.2.x before 7.2.5. There is Reflected XSS
    on the PHAR 403 and 404 error pages via request data of
    a request for a .phar file. NOTE: this vulnerability
    exists because of an incomplete fix for
    CVE-2018-5712.(CVE-2018-10547)

  - The Apache2 component in PHP before 5.6.38, 7.0.x
    before 7.0.32, 7.1.x before 7.1.22, and 7.2.x before
    7.2.10 allows XSS via the body of a 'Transfer-Encoding:
    chunked' request, because the bucket brigade is
    mishandled in the php_handler function in
    sapi/apache2handler/sapi_apache2.c.(CVE-2018-17082)

  - PHP through 7.1.11 enables potential SSRF in
    applications that accept an fsockopen or pfsockopen
    hostname argument with an expectation that the port
    number is constrained. Because a :port syntax is
    recognized, fsockopen will use the port number that is
    specified in the hostname argument, instead of the port
    number in the second argument of the
    function.(CVE-2017-7272 )

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, a stack-based buffer overflow in the
    zend_ini_do_op() function in Zend/zend_ini_parser.c
    could cause a denial of service or potentially allow
    executing code. NOTE: this is only relevant for PHP
    applications that accept untrusted input (instead of
    the system's php.ini file) for the parse_ini_string or
    parse_ini_file function, e.g., a web application for
    syntax validation of php.ini
    directives.(CVE-2017-11628)

  - In PHP before 5.6.30 and 7.x before 7.0.15, the PHAR
    archive handler could be used by attackers supplying
    malicious archive files to crash the PHP interpreter or
    potentially disclose information due to a buffer
    over-read in the phar_parse_pharfile function in
    ext/phar/phar.c.(CVE-2017-11147)

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, the openssl extension PEM sealing code
    did not check the return value of the OpenSSL sealing
    function, which could lead to a crash of the PHP
    interpreter, related to an interpretation conflict for
    a negative number in ext/openssl/openssl.c, and an
    OpenSSL documentation omission.(CVE-2017-11144)

  - The locale_accept_from_http function in
    ext/intl/locale/locale_methods.c in PHP before 5.5.38,
    5.6.x before 5.6.24, and 7.x before 7.0.9 does not
    properly restrict calls to the ICU
    uloc_acceptLanguageFromHTTP function, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a call with a long argument.(CVE-2016-6294)

  - Session fixation vulnerability in the Sessions
    subsystem in PHP before 5.5.2 allows remote attackers
    to hijack web sessions by specifying a session
    ID.(CVE-2011-4718)

  - Off-by-one error in the phar_parse_zipfile function in
    ext/phar/zip.c in PHP before 5.5.30 and 5.6.x before
    5.6.14 allows remote attackers to cause a denial of
    service (uninitialized pointer dereference and
    application crash) by including the / filename in a
    .zip PHAR archive.(CVE-2015-7804)

  - The php_wddx_push_element function in ext/wddx/wddx.c
    in PHP before 5.6.26 and 7.x before 7.0.11 allows
    remote attackers to cause a denial of service (invalid
    pointer access and out-of-bounds read) or possibly have
    unspecified other impact via an incorrect boolean
    element in a wddxPacket XML document, leading to
    mishandling in a wddx_deserialize call.(CVE-2016-7418)

  - The exif_process_user_comment function in
    ext/exif/exif.c in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9 allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) via a crafted JPEG
    image.(CVE-2016-6292)

  - The make_http_soap_request function in
    ext/soap/php_http.c in PHP before 5.4.44, 5.5.x before
    5.5.28, 5.6.x before 5.6.12, and 7.x before 7.0.4
    allows remote attackers to obtain sensitive information
    from process memory or cause a denial of service (type
    confusion and application crash) via crafted serialized
    _cookies data, related to the SoapClient::__call method
    in ext/soap/soap.c.(CVE-2016-3185)

  - Directory traversal vulnerability in the
    ZipArchive::extractTo function in ext/zip/php_zip.c in
    PHP before 5.4.45, 5.5.x before 5.5.29, and 5.6.x
    before 5.6.13 and ext/zip/ext_zip.cpp in HHVM before
    3.12.1 allows remote attackers to create arbitrary
    empty directories via a crafted ZIP
    archive.(CVE-2014-9767)

  - The phar_convert_to_other function in
    ext/phar/phar_object.c in PHP before 5.4.43, 5.5.x
    before 5.5.27, and 5.6.x before 5.6.11 does not
    validate a file pointer before a close operation, which
    allows remote attackers to cause a denial of service
    (segmentation fault) or possibly have unspecified other
    impact via a crafted TAR archive that is mishandled in
    a Phar::convertToData call.(CVE-2015-5589)

  - Directory traversal vulnerability in the PharData class
    in PHP before 5.4.44, 5.5.x before 5.5.28, and 5.6.x
    before 5.6.12 allows remote attackers to write to
    arbitrary files via a .. (dot dot) in a ZIP archive
    entry that is mishandled during an extractTo
    call.(CVE-2015-6833)

  - The phar_get_entry_data function in ext/phar/util.c in
    PHP before 5.5.30 and 5.6.x before 5.6.14 allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and application crash) via a .phar file
    with a crafted TAR archive entry in which the Link
    indicator references a file that does not
    exist.(CVE-2015-7803)

  - Stack consumption vulnerability in GD in PHP before
    5.6.12 allows remote attackers to cause a denial of
    service via a crafted imagefilltoborder
    call.(CVE-2015-8874)

  - Stack-based buffer overflow in ext/phar/tar.c in PHP
    before 5.5.32, 5.6.x before 5.6.18, and 7.x before
    7.0.3 allows remote attackers to cause a denial of
    service (application crash) or possibly have
    unspecified other impact via a crafted TAR
    archive.(CVE-2016-2554)

  - The phar_parse_zipfile function in zip.c in the PHAR
    extension in PHP before 5.5.33 and 5.6.x before 5.6.19
    allows remote attackers to obtain sensitive information
    from process memory or cause a denial of service
    (out-of-bounds read and application crash) by placing a
    PK\x05\x06 signature at an invalid
    location.(CVE-2016-3142)

  - ext/session/session.c in PHP before 5.6.25 and 7.x
    before 7.0.10 skips invalid session names in a way that
    triggers incorrect parsing, which allows remote
    attackers to inject arbitrary-type session data by
    leveraging control of a session name, as demonstrated
    by object injection.(CVE-2016-7125)

  - The exif_process_IFD_in_TIFF function in
    ext/exif/exif.c in PHP before 5.6.25 and 7.x before
    7.0.10 mishandles the case of a thumbnail offset that
    exceeds the file size, which allows remote attackers to
    obtain sensitive information from process memory via a
    crafted TIFF image.(CVE-2016-7128)

  - The get_icu_disp_value_src_php function in
    ext/intl/locale/locale_methods.c in PHP before 5.3.29,
    5.4.x before 5.4.30, and 5.5.x before 5.5.14 does not
    properly restrict calls to the ICU uresbund.cpp
    component, which allows remote attackers to cause a
    denial of service (buffer overflow) or possibly have
    unspecified other impact via a locale_get_display_name
    call with a long first argument.(CVE-2014-9912)

  - Use-after-free vulnerability in the SPL unserialize
    implementation in ext/spl/spl_array.c in PHP before
    5.4.44, 5.5.x before 5.5.28, and 5.6.x before 5.6.12
    allows remote attackers to execute arbitrary code via
    crafted serialized data that triggers misuse of an
    array field.(CVE-2015-6832)

  - The make_http_soap_request function in
    ext/soap/php_http.c in PHP before 5.4.44, 5.5.x before
    5.5.28, and 5.6.x before 5.6.12 does not properly
    retrieve keys, which allows remote attackers to cause a
    denial of service (NULL pointer dereference, type
    confusion, and application crash) or possibly execute
    arbitrary code via crafted serialized data representing
    a numerically indexed _cookies array, related to the
    SoapClient::__call method in
    ext/soap/soap.c.(CVE-2015-8835)

  - The uloc_acceptLanguageFromHTTP function in
    common/uloc.cpp in International Components for Unicode
    (ICU) through 57.1 for C/C++ does not ensure that there
    is a '\0' character at the end of a certain temporary
    array, which allows remote attackers to cause a denial
    of service (out-of-bounds read) or possibly have
    unspecified other impact via a call with a long
    httpAcceptLanguage argument.(CVE-2016-6293)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.30, 7.2.x below 7.2.19 and
    7.3.x below 7.3.6 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11040)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and
    7.3.x below 7.3.8 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11041)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and
    7.3.x below 7.3.8 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11042)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2438
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?72902c09");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2554");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-11043");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-42.h63",
        "php-cli-5.4.16-42.h63",
        "php-common-5.4.16-42.h63",
        "php-gd-5.4.16-42.h63",
        "php-ldap-5.4.16-42.h63",
        "php-mysql-5.4.16-42.h63",
        "php-odbc-5.4.16-42.h63",
        "php-pdo-5.4.16-42.h63",
        "php-pgsql-5.4.16-42.h63",
        "php-process-5.4.16-42.h63",
        "php-recode-5.4.16-42.h63",
        "php-soap-5.4.16-42.h63",
        "php-xml-5.4.16-42.h63",
        "php-xmlrpc-5.4.16-42.h63"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
