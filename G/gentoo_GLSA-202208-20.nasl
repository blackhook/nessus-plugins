#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202208-20.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(164114);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/07");

  script_cve_id(
    "CVE-2021-33193",
    "CVE-2021-34798",
    "CVE-2021-36160",
    "CVE-2021-39275",
    "CVE-2021-40438",
    "CVE-2021-41524",
    "CVE-2021-41773",
    "CVE-2021-42013",
    "CVE-2021-44224",
    "CVE-2021-44790",
    "CVE-2022-22719",
    "CVE-2022-22720",
    "CVE-2022-22721",
    "CVE-2022-23943",
    "CVE-2022-26377",
    "CVE-2022-28614",
    "CVE-2022-28615",
    "CVE-2022-29404",
    "CVE-2022-30522",
    "CVE-2022-30556",
    "CVE-2022-31813"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/12/15");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0046");

  script_name(english:"GLSA-202208-20 : Apache HTTPD: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202208-20 (Apache HTTPD: Multiple Vulnerabilities)

  - A crafted method sent through HTTP/2 will bypass validation and be forwarded by mod_proxy, which can lead
    to request splitting or cache poisoning. This issue affects Apache HTTP Server 2.4.17 to 2.4.48.
    (CVE-2021-33193)

  - Malformed requests may cause the server to dereference a NULL pointer. This issue affects Apache HTTP
    Server 2.4.48 and earlier. (CVE-2021-34798)

  - A carefully crafted request uri-path can cause mod_proxy_uwsgi to read above the allocated memory and
    crash (DoS). This issue affects Apache HTTP Server versions 2.4.30 to 2.4.48 (inclusive). (CVE-2021-36160)

  - ap_escape_quotes() may write beyond the end of a buffer when given malicious input. No included modules
    pass untrusted data to these functions, but third-party / external modules may. This issue affects Apache
    HTTP Server 2.4.48 and earlier. (CVE-2021-39275)

  - A crafted request uri-path can cause mod_proxy to forward the request to an origin server choosen by the
    remote user. This issue affects Apache HTTP Server 2.4.48 and earlier. (CVE-2021-40438)

  - While fuzzing the 2.4.49 httpd, a new null pointer dereference was detected during HTTP/2 request
    processing, allowing an external source to DoS the server. This requires a specially crafted request. The
    vulnerability was recently introduced in version 2.4.49. No exploit is known to the project.
    (CVE-2021-41524)

  - A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49. An attacker could
    use a path traversal attack to map URLs to files outside the directories configured by Alias-like
    directives. If files outside of these directories are not protected by the usual default configuration
    require all denied, these requests can succeed. If CGI scripts are also enabled for these aliased
    pathes, this could allow for remote code execution. This issue is known to be exploited in the wild. This
    issue only affects Apache 2.4.49 and not earlier versions. The fix in Apache HTTP Server 2.4.50 was found
    to be incomplete, see CVE-2021-42013. (CVE-2021-41773)

  - It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker
    could use a path traversal attack to map URLs to files outside the directories configured by Alias-like
    directives. If files outside of these directories are not protected by the usual default configuration
    require all denied, these requests can succeed. If CGI scripts are also enabled for these aliased
    pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache
    2.4.50 and not earlier versions. (CVE-2021-42013)

  - A crafted URI sent to httpd configured as a forward proxy (ProxyRequests on) can cause a crash (NULL
    pointer dereference) or, for configurations mixing forward and reverse proxy declarations, can allow for
    requests to be directed to a declared Unix Domain Socket endpoint (Server Side Request Forgery). This
    issue affects Apache HTTP Server 2.4.7 up to 2.4.51 (included). (CVE-2021-44224)

  - A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser
    (r:parsebody() called from Lua scripts). The Apache httpd team is not aware of an exploit for the
    vulnerability though it might be possible to craft one. This issue affects Apache HTTP Server 2.4.51 and
    earlier. (CVE-2021-44790)

  - A carefully crafted request body can cause a read to a random memory area which could cause the process to
    crash. This issue affects Apache HTTP Server 2.4.52 and earlier. (CVE-2022-22719)

  - Apache HTTP Server 2.4.52 and earlier fails to close inbound connection when errors are encountered
    discarding the request body, exposing the server to HTTP Request Smuggling (CVE-2022-22720)

  - If LimitXMLRequestBody is set to allow request bodies larger than 350MB (defaults to 1M) on 32 bit systems
    an integer overflow happens which later causes out of bounds writes. This issue affects Apache HTTP Server
    2.4.52 and earlier. (CVE-2022-22721)

  - Out-of-bounds Write vulnerability in mod_sed of Apache HTTP Server allows an attacker to overwrite heap
    memory with possibly attacker provided data. This issue affects Apache HTTP Server 2.4 version 2.4.52 and
    prior versions. (CVE-2022-23943)

  - Inconsistent Interpretation of HTTP Requests ('HTTP Request Smuggling') vulnerability in mod_proxy_ajp of
    Apache HTTP Server allows an attacker to smuggle requests to the AJP server it forwards requests to. This
    issue affects Apache HTTP Server Apache HTTP Server 2.4 version 2.4.53 and prior versions.
    (CVE-2022-26377)

  - The ap_rwrite() function in Apache HTTP Server 2.4.53 and earlier may read unintended memory if an
    attacker can cause the server to reflect very large input using ap_rwrite() or ap_rputs(), such as with
    mod_luas r:puts() function. Modules compiled and distributed separately from Apache HTTP Server that use
    the 'ap_rputs' function and may pass it a very large (INT_MAX or larger) string must be compiled against
    current headers to resolve the issue. (CVE-2022-28614)

  - Apache HTTP Server 2.4.53 and earlier may crash or disclose information due to a read beyond bounds in
    ap_strcmp_match() when provided with an extremely large input buffer. While no code distributed with the
    server can be coerced into such a call, third-party modules or lua scripts that use ap_strcmp_match() may
    hypothetically be affected. (CVE-2022-28615)

  - In Apache HTTP Server 2.4.53 and earlier, a malicious request to a lua script that calls r:parsebody(0)
    may cause a denial of service due to no default limit on possible input size. (CVE-2022-29404)

  - If Apache HTTP Server 2.4.53 is configured to do transformations with mod_sed in contexts where the input
    to mod_sed may be very large, mod_sed may make excessively large memory allocations and trigger an abort.
    (CVE-2022-30522)

  - Apache HTTP Server 2.4.53 and earlier may return lengths to applications calling r:wsread() that point
    past the end of the storage allocated for the buffer. (CVE-2022-30556)

  - Apache HTTP Server 2.4.53 and earlier may not send the X-Forwarded-* headers to the origin server based on
    client side Connection header hop-by-hop mechanism. This may be used to bypass IP based authentication on
    the origin server/application. (CVE-2022-31813)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202208-20");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=813429");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816399");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=816864");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=829722");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=835131");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=850622");
  script_set_attribute(attribute:"solution", value:
"All Apache HTTPD users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=www-servers/apache-2.4.54
        
All Apache HTTPD tools users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=app-admin/apache-tools-2.4.54");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-31813");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:apache-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : "app-admin/apache-tools",
    'unaffected' : make_list("ge 2.4.54"),
    'vulnerable' : make_list("lt 2.4.54")
  },
  {
    'name' : "www-servers/apache",
    'unaffected' : make_list("ge 2.4.54"),
    'vulnerable' : make_list("lt 2.4.54")
  }
];

foreach package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Apache HTTPD");
}
