#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(137966);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/25");

  script_cve_id(
    "CVE-2011-4718",
    "CVE-2014-9767",
    "CVE-2014-9912",
    "CVE-2015-4116",
    "CVE-2015-6831",
    "CVE-2015-6832",
    "CVE-2015-6833",
    "CVE-2015-7803",
    "CVE-2015-7804",
    "CVE-2015-8866",
    "CVE-2015-8867",
    "CVE-2015-8874",
    "CVE-2015-8879",
    "CVE-2015-8935",
    "CVE-2016-10158",
    "CVE-2016-10159",
    "CVE-2016-10161",
    "CVE-2016-10397",
    "CVE-2016-2554",
    "CVE-2016-3141",
    "CVE-2016-3142",
    "CVE-2016-3185",
    "CVE-2016-4070",
    "CVE-2016-4073",
    "CVE-2016-4539",
    "CVE-2016-4540",
    "CVE-2016-4542",
    "CVE-2016-5093",
    "CVE-2016-5094",
    "CVE-2016-5772",
    "CVE-2016-6288",
    "CVE-2016-6291",
    "CVE-2016-6292",
    "CVE-2016-6294",
    "CVE-2016-7124",
    "CVE-2016-7125",
    "CVE-2016-7128",
    "CVE-2016-7412",
    "CVE-2016-7414",
    "CVE-2016-7418",
    "CVE-2016-9934",
    "CVE-2016-9935",
    "CVE-2017-11143",
    "CVE-2017-11144",
    "CVE-2017-11145",
    "CVE-2017-11147",
    "CVE-2017-11628",
    "CVE-2017-12933",
    "CVE-2017-16642",
    "CVE-2017-7272",
    "CVE-2017-9226",
    "CVE-2018-10545",
    "CVE-2018-10547",
    "CVE-2018-14851",
    "CVE-2018-17082",
    "CVE-2018-5711",
    "CVE-2018-5712",
    "CVE-2019-11041",
    "CVE-2019-11042",
    "CVE-2019-11043",
    "CVE-2019-11047",
    "CVE-2019-11050",
    "CVE-2019-19204",
    "CVE-2019-19246",
    "CVE-2019-9641"
  );
  script_bugtraq_id(61929);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");
  script_xref(name:"CEA-ID", value:"CEA-2019-0695");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : php (EulerOS-SA-2020-1747)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and
    7.3.x below 7.3.8 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11042)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.1.x below 7.1.31, 7.2.x below 7.2.21 and
    7.3.x below 7.3.8 it is possible to supply it with data
    what will cause it to read past the allocated buffer.
    This may lead to information disclosure or
    crash.(CVE-2019-11041)

  - An issue was discovered in PHP before 5.6.33, 7.0.x
    before 7.0.27, 7.1.x before 7.1.13, and 7.2.x before
    7.2.1. There is Reflected XSS on the PHAR 404 error
    page via the URI of a request for a .phar
    file.(CVE-2018-5712)

  - gd_gif_in.c in the GD Graphics Library (aka libgd), as
    used in PHP before 5.6.33, 7.0.x before 7.0.27, 7.1.x
    before 7.1.13, and 7.2.x before 7.2.1, has an integer
    signedness error that leads to an infinite loop via a
    crafted GIF file, as demonstrated by a call to the
    imagecreatefromgif or imagecreatefromstring PHP
    function. This is related to GetCode_ and
    gdImageCreateFromGifCtx.(CVE-2018-5711)

  - The Apache2 component in PHP before 5.6.38, 7.0.x
    before 7.0.32, 7.1.x before 7.1.22, and 7.2.x before
    7.2.10 allows XSS via the body of a 'Transfer-Encoding:
    chunked' request, because the bucket brigade is
    mishandled in the php_handler function in
    sapi/apache2handler/sapi_apache2.c.(CVE-2018-17082)

  - exif_process_IFD_in_MAKERNOTE in ext/exif/exif.c in PHP
    before 5.6.37, 7.0.x before 7.0.31, 7.1.x before
    7.1.20, and 7.2.x before 7.2.8 allows remote attackers
    to cause a denial of service (out-of-bounds read and
    application crash) via a crafted JPEG
    file.(CVE-2018-14851)

  - An issue was discovered in ext/phar/phar_object.c in
    PHP before 5.6.36, 7.0.x before 7.0.30, 7.1.x before
    7.1.17, and 7.2.x before 7.2.5. There is Reflected XSS
    on the PHAR 403 and 404 error pages via request data of
    a request for a .phar file. NOTE: this vulnerability
    exists because of an incomplete fix for
    CVE-2018-5712.(CVE-2018-10547)

  - An issue was discovered in PHP before 5.6.35, 7.0.x
    before 7.0.29, 7.1.x before 7.1.16, and 7.2.x before
    7.2.4. Dumpable FPM child processes allow bypassing
    opcache access controls because fpm_unix.c makes a
    PR_SET_DUMPABLE prctl call, allowing one user (in a
    multiuser environment) to obtain sensitive information
    from the process memory of a second user's PHP
    applications by running gcore on the PID of the PHP-FPM
    worker process.(CVE-2018-10545)

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

  - The php_wddx_push_element function in ext/wddx/wddx.c
    in PHP before 5.6.26 and 7.x before 7.0.11 allows
    remote attackers to cause a denial of service (invalid
    pointer access and out-of-bounds read) or possibly have
    unspecified other impact via an incorrect boolean
    element in a wddxPacket XML document, leading to
    mishandling in a wddx_deserialize call.(CVE-2016-7418)

  - The exif_process_IFD_in_TIFF function in
    ext/exif/exif.c in PHP before 5.6.25 and 7.x before
    7.0.10 mishandles the case of a thumbnail offset that
    exceeds the file size, which allows remote attackers to
    obtain sensitive information from process memory via a
    crafted TIFF image.(CVE-2016-7128)

  - ext/session/session.c in PHP before 5.6.25 and 7.x
    before 7.0.10 skips invalid session names in a way that
    triggers incorrect parsing, which allows remote
    attackers to inject arbitrary-type session data by
    leveraging control of a session name, as demonstrated
    by object injection.(CVE-2016-7125)

  - The locale_accept_from_http function in
    ext/intl/locale/locale_methods.c in PHP before 5.5.38,
    5.6.x before 5.6.24, and 7.x before 7.0.9 does not
    properly restrict calls to the ICU
    uloc_acceptLanguageFromHTTP function, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a call with a long argument.(CVE-2016-6294)

  - The exif_process_user_comment function in
    ext/exif/exif.c in PHP before 5.5.38, 5.6.x before
    5.6.24, and 7.x before 7.0.9 allows remote attackers to
    cause a denial of service (NULL pointer dereference and
    application crash) via a crafted JPEG
    image.(CVE-2016-6292)

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

  - Integer overflow in the phar_parse_pharfile function in
    ext/phar/phar.c in PHP before 5.6.30 and 7.0.x before
    7.0.15 allows remote attackers to cause a denial of
    service (memory consumption or application crash) via a
    truncated manifest entry in a PHAR
    archive.(CVE-2016-10159)

  - It was found that the exif_convert_any_to_int()
    function in PHP was vulnerable to floating point
    exceptions when parsing tags in image files. A remote
    attacker with the ability to upload a malicious image
    could crash PHP, causing a Denial of
    Service.(CVE-2016-10158)

  - Stack consumption vulnerability in GD in PHP before
    5.6.12 allows remote attackers to cause a denial of
    service via a crafted imagefilltoborder
    call.(CVE-2015-8874)

  - ext/libxml/libxml.c in PHP before 5.5.22 and 5.6.x
    before 5.6.6, when PHP-FPM is used, does not isolate
    each thread from libxml_disable_entity_loader changes
    in other threads, which allows remote attackers to
    conduct XML External Entity (XXE) and XML Entity
    Expansion (XEE) attacks via a crafted XML document, a
    related issue to CVE-2015-5161.(CVE-2015-8866)

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-7804)

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-7803)

  - Use-after-free vulnerability in the spl_ptr_heap_insert
    function in ext/spl/spl_heap.c in PHP before 5.5.27 and
    5.6.x before 5.6.11 allows remote attackers to execute
    arbitrary code by triggering a failed
    SplMinHeap::compare operation.(CVE-2015-4116)

  - The get_icu_disp_value_src_php function in
    ext/intl/locale/locale_methods.c in PHP before 5.3.29,
    5.4.x before 5.4.30, and 5.5.x before 5.5.14 does not
    properly restrict calls to the ICU uresbund.cpp
    component, which allows remote attackers to cause a
    denial of service (buffer overflow) or possibly have
    unspecified other impact via a locale_get_display_name
    call with a long first argument.(CVE-2014-9912)

  - The header() PHP function allowed header stings
    containing line break followed by a space or tab, as
    allowed by RFC 2616. Certain browsers handled the
    continuation line as new header, making it possible to
    conduct a HTTP response splitting attack against such
    browsers. The header() function was updated to follow
    RFC 7230 and not allow any line breaks.(CVE-2015-8935)

  - The openssl_random_pseudo_bytes function in
    ext/openssl/openssl.c in PHP before 5.4.44, 5.5.x
    before 5.5.28, and 5.6.x before 5.6.12 incorrectly
    relies on the deprecated RAND_pseudo_bytes function,
    which makes it easier for remote attackers to defeat
    cryptographic protection mechanisms via unspecified
    vectors.(CVE-2015-8867)

  - A flaw was found in the way the way PHP's Phar
    extension parsed Phar archives. A specially crafted
    archive could cause PHP to crash or, possibly, execute
    arbitrary code when opened.(CVE-2015-6833)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-6832)

  - Directory traversal vulnerability in the
    ZipArchive::extractTo function in ext/zip/php_zip.c in
    PHP before 5.4.45, 5.5.x before 5.5.29, and 5.6.x
    before 5.6.13 and ext/zip/ext_zip.cpp in HHVM before
    3.12.1 allows remote attackers to create arbitrary
    empty directories via a crafted ZIP
    archive.(CVE-2014-9767)

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

  - Integer overflow in the php_html_entities function in
    ext/standard/html.c in PHP before 5.5.36 and 5.6.x
    before 5.6.22 allows remote attackers to cause a denial
    of service or possibly have unspecified other impact by
    triggering a large output string from the
    htmlspecialchars function.(CVE-2016-5094)

  - The get_icu_value_internal function in
    ext/intl/locale/locale_methods.c in PHP before 5.5.36,
    5.6.x before 5.6.22, and 7.x before 7.0.7 does not
    ensure the presence of a '\\0' character, which allows
    remote attackers to cause a denial of service
    (out-of-bounds read) or possibly have unspecified other
    impact via a crafted locale_get_primary_language
    call.(CVE-2016-5093)

  - The exif_process_IFD_TAG function in ext/exif/exif.c in
    PHP before 5.5.35, 5.6.x before 5.6.21, and 7.x before
    7.0.6 does not properly construct spprintf arguments,
    which allows remote attackers to cause a denial of
    service (out-of-bounds read) or possibly have
    unspecified other impact via crafted header
    data.(CVE-2016-4542)

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

  - The phar_parse_zipfile function in zip.c in the PHAR
    extension in PHP before 5.5.33 and 5.6.x before 5.6.19
    allows remote attackers to obtain sensitive information
    from process memory or cause a denial of service
    (out-of-bounds read and application crash) by placing a
    PK\\x05\\x06 signature at an invalid
    location.(CVE-2016-3142)

  - Use-after-free vulnerability in wddx.c in the WDDX
    extension in PHP before 5.5.33 and 5.6.x before 5.6.19
    allows remote attackers to cause a denial of service
    (memory corruption and application crash) or possibly
    have unspecified other impact by triggering a
    wddx_deserialize call on XML data containing a crafted
    var element.(CVE-2016-3141)

  - The odbc_bindcols function in ext/odbc/php_odbc.c in
    PHP before 5.6.12 mishandles driver behavior for
    SQL_WVARCHAR columns, which allows remote attackers to
    cause a denial of service (application crash) in
    opportunistic circumstances by leveraging use of the
    odbc_fetch_array function to access a certain type of
    Microsoft SQL Server table.(CVE-2015-8879)

  - In PHP before 5.6.30 and 7.x before 7.0.15, the PHAR
    archive handler could be used by attackers supplying
    malicious archive files to crash the PHP interpreter or
    potentially disclose information due to a buffer
    over-read in the phar_parse_pharfile function in
    ext/phar/phar.c.(CVE-2017-11147)

  - ext/standard/var_unserializer.c in PHP before 5.6.25
    and 7.x before 7.0.10 mishandles certain invalid
    objects, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via crafted serialized data that leads to a (1)
    __destruct call or (2) magic method
    call.(CVE-2016-7124)

  - Stack-based buffer overflow in ext/phar/tar.c in PHP
    before 5.5.32, 5.6.x before 5.6.18, and 7.x before
    7.0.3 allows remote attackers to cause a denial of
    service (application crash) or possibly have
    unspecified other impact via a crafted TAR
    archive.(CVE-2016-2554)

  - A flaw was discovered in the way PHP performed object
    unserialization. Specially crafted input processed by
    the unserialize() function could cause a PHP
    application to crash or, possibly, execute arbitrary
    code.(CVE-2015-6831)

  - The make_http_soap_request function in
    ext/soap/php_http.c in PHP before 5.4.44, 5.5.x before
    5.5.28, 5.6.x before 5.6.12, and 7.x before 7.0.4
    allows remote attackers to obtain sensitive information
    from process memory or cause a denial of service (type
    confusion and application crash) via crafted serialized
    _cookies data, related to the SoapClient::__call method
    in ext/soap/soap.c.(CVE-2016-3185)

  - The object_common1 function in
    ext/standard/var_unserializer.c in PHP before 5.6.30,
    7.0.x before 7.0.15, and 7.1.x before 7.1.1 allows
    remote attackers to cause a denial of service (buffer
    over-read and application crash) via crafted serialized
    data that is mishandled in a finish_nested_data
    call.(CVE-2016-10161)

  - The finish_nested_data function in
    ext/standard/var_unserializer.re in PHP before 5.6.31,
    7.0.x before 7.0.21, and 7.1.x before 7.1.7 is prone to
    a buffer over-read while unserializing untrusted data.
    Exploitation of this issue can have an unspecified
    impact on the integrity of PHP.(CVE-2017-12933)

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, the openssl extension PEM sealing code
    did not check the return value of the OpenSSL sealing
    function, which could lead to a crash of the PHP
    interpreter, related to an interpretation conflict for
    a negative number in ext/openssl/openssl.c, and an
    OpenSSL documentation omission.(CVE-2017-11144)

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

  - In PHP versions 7.1.x below 7.1.33, 7.2.x below 7.2.24
    and 7.3.x below 7.3.11 in certain configurations of FPM
    setup it is possible to cause FPM module to write past
    allocated buffers into the space reserved for FCGI
    protocol data, thus opening the possibility of remote
    code execution.(CVE-2019-11043)

  - Session fixation vulnerability in the Sessions
    subsystem in PHP before 5.5.2 allows remote attackers
    to hijack web sessions by specifying a session
    ID.(CVE-2011-4718)

  - In PHP before 5.6.32, 7.x before 7.0.25, and 7.1.x
    before 7.1.11, an error in the date extension's
    timelib_meridian handling of 'front of' and 'back of'
    directives could be used by attackers able to supply
    date strings to leak information from the interpreter,
    related to ext/date/lib/parse_date.c out-of-bounds
    reads affecting the php_parse_date function. NOTE: this
    is a different issue than
    CVE-2017-11145.(CVE-2017-16642)

  - In PHP before 5.6.31, 7.x before 7.0.21, and 7.1.x
    before 7.1.7, an error in the date extension's
    timelib_meridian parsing code could be used by
    attackers able to supply date strings to leak
    information from the interpreter, related to
    ext/date/lib/parse_date.c out-of-bounds reads affecting
    the php_parse_date function. NOTE: the correct fix is
    in the e8b7698f5ee757ce2c8bd10a192a491a498f891c commit,
    not the bd77ac90d3bdf31ce2a5251ad92e9e75
    gist.(CVE-2017-11145)

  - In PHP before 5.6.28 and 7.x before 7.0.13, incorrect
    handling of various URI components in the URL parser
    could be used by attackers to bypass hostname-specific
    URL checks, as demonstrated by
    evil.example.com:80#@good.example.com/ and
    evil.example.com:80?@good.example.com/ inputs to the
    parse_url function (implemented in the php_url_parse_ex
    function in ext/standard/url.c).(CVE-2016-10397)

  - ext/mysqlnd/mysqlnd_wireprotocol.c in PHP before 5.6.26
    and 7.x before 7.0.11 does not verify that a BIT field
    has the UNSIGNED_FLAG flag, which allows remote MySQL
    servers to cause a denial of service (heap-based buffer
    overflow) or possibly have unspecified other impact via
    crafted field metadata.(CVE-2016-7412)

  - Oniguruma through 6.9.3, as used in PHP 7.3.x and other
    products, has a heap-based buffer over-read in
    str_lower_case_match in regexec.c.(CVE-2019-19246)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and
    7.4.0 it is possible to supply it with data what will
    cause it to read past the allocated buffer. This may
    lead to information disclosure or
    crash.(CVE-2019-11047)

  - PHP through 7.1.11 enables potential SSRF in
    applications that accept an fsockopen or pfsockopen
    hostname argument with an expectation that the port
    number is constrained. Because a :port syntax is
    recognized, fsockopen will use the port number that is
    specified in the hostname argument, instead of the port
    number in the second argument of the
    function.(CVE-2017-7272)

  - When PHP EXIF extension is parsing EXIF information
    from an image, e.g. via exif_read_data() function, in
    PHP versions 7.2.x below 7.2.26, 7.3.x below 7.3.13 and
    7.4.0 it is possible to supply it with data what will
    cause it to read past the allocated buffer. This may
    lead to information disclosure or
    crash.(CVE-2019-11050)

  - An issue was discovered in Oniguruma 6.x before
    6.9.4_rc2. In the function fetch_interval_quantifier
    (formerly known as fetch_range_quantifier) in
    regparse.c, PFETCH is called without checking PEND.
    This leads to a heap-based buffer
    over-read.(CVE-2019-19204)

  - An issue was discovered in the EXIF component in PHP
    before 7.1.27, 7.2.x before 7.2.16, and 7.3.x before
    7.3.3. There is an uninitialized read in
    exif_process_IFD_in_TIFF.(CVE-2019-9641)

  - Double free vulnerability in the php_wddx_process_data
    function in wddx.c in the WDDX extension in PHP before
    5.5.37, 5.6.x before 5.6.23, and 7.x before 7.0.8
    allows remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via crafted XML data that is mishandled in a
    wddx_deserialize call.(CVE-2016-5772)

  - Multiple integer overflows in the mbfl_strcut function
    in ext/mbstring/libmbfl/mbfl/mbfilter.c in PHP before
    5.5.34, 5.6.x before 5.6.20, and 7.x before 7.0.5 allow
    remote attackers to cause a denial of service
    (application crash) or possibly execute arbitrary code
    via a crafted mb_strcut call.(CVE-2016-4073)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1747
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dda25e7c");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2554");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9641");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP-FPM Underflow RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h30",
        "php-cli-5.4.16-45.h30",
        "php-common-5.4.16-45.h30"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
