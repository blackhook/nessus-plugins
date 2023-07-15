#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(48244);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2007-1581",
    "CVE-2010-0397",
    "CVE-2010-1860",
    "CVE-2010-1862",
    "CVE-2010-1864",
    "CVE-2010-2097",
    "CVE-2010-2100",
    "CVE-2010-2101",
    "CVE-2010-2190",
    "CVE-2010-2191",
    "CVE-2010-2225",
    "CVE-2010-2484",
    "CVE-2010-2531",
    "CVE-2010-3065"
  );
  script_bugtraq_id(38708, 40948, 41991);
  script_xref(name:"SECUNIA", value:"39675");
  script_xref(name:"SECUNIA", value:"40268");

  script_name(english:"PHP 5.2 < 5.2.14 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a version of PHP that is affected by
multiple flaws.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of PHP 5.2 installed on the
remote host is older than 5.2.14.  Such versions may be affected by
several security issues :

  - An error exists when processing invalid XML-RPC 
    requests that can lead to a NULL pointer
    dereference. (bug #51288) (CVE-2010-0397)

  - An error exists in the function 'fnmatch' that can lead
    to stack exhaustion.

  - An error exists in the sqlite extension that could 
    allow arbitrary memory access.

  - A memory corruption error exists in the function
    'substr_replace'.

  - The following functions are not properly protected
    against function interruptions :

    addcslashes, chunk_split, html_entity_decode, 
    iconv_mime_decode, iconv_substr, iconv_mime_encode,
    htmlentities, htmlspecialchars, str_getcsv,
    http_build_query, strpbrk, strstr, str_pad,
    str_word_count, wordwrap, strtok, setcookie, 
    strip_tags, trim, ltrim, rtrim, parse_str, pack, unpack, 
    uasort, preg_match, strrchr, strchr, substr, str_repeat
    (CVE-2010-1860, CVE-2010-1862, CVE-2010-1864,
    CVE-2010-2097, CVE-2010-2100, CVE-2010-2101,
    CVE-2010-2190, CVE-2010-2191, CVE-2010-2484)

  - The following opcodes are not properly protected 
    against function interruptions :

    ZEND_CONCAT, ZEND_ASSIGN_CONCAT, ZEND_FETCH_RW
    (CVE-2010-2191)

  - The default session serializer contains an error
    that can be exploited when assigning session
    variables having user defined names. Arbitrary
    serialized values can be injected into sessions by
    including the PS_UNDEF_MARKER, '!', character in
    variable names.

  - A use-after-free error exists in the function
    'spl_object_storage_attach'. (CVE-2010-2225)

  - An information disclosure vulnerability exists in the
    function 'var_export' when handling certain error 
    conditions. (CVE-2010-2531)");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/releases/5_2_14.php");
  script_set_attribute(attribute:"see_also", value:"http://www.php.net/ChangeLog-5.php#5.2.14");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PHP version 5.2.14 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2022 Tenable Network Security, Inc.");

  script_dependencies("php_version.nasl");
  script_require_keys("www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("audit.inc");
include("webapp_func.inc");

port = get_http_port(default:80, php:TRUE);

php = get_php_from_kb(
  port : port,
  exit_on_fail : TRUE
);

version = php["ver"];
source = php["src"];

backported = get_kb_item('www/php/'+port+'/'+version+'/backported');

if (report_paranoia < 2 && backported)
  audit(AUDIT_BACKPORT_SERVICE, port, "PHP "+version+" install");

if (version =~ "^5\.2\.([0-9]|1[0-3])($|[^0-9])")
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source     : '+source +
      '\n  Installed version  : '+version+
      '\n  Fixed version      : 5.2.14\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "PHP", port, version);
