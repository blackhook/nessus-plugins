#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77811);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/23");

  script_cve_id(
    "CVE-2013-6629",
    "CVE-2013-6954",
    "CVE-2014-0429",
    "CVE-2014-0446",
    "CVE-2014-0448",
    "CVE-2014-0449",
    "CVE-2014-0451",
    "CVE-2014-0452",
    "CVE-2014-0453",
    "CVE-2014-0454",
    "CVE-2014-0455",
    "CVE-2014-0457",
    "CVE-2014-0458",
    "CVE-2014-0459",
    "CVE-2014-0460",
    "CVE-2014-0461",
    "CVE-2014-0963",
    "CVE-2014-1876",
    "CVE-2014-2398",
    "CVE-2014-2401",
    "CVE-2014-2402",
    "CVE-2014-2409",
    "CVE-2014-2412",
    "CVE-2014-2414",
    "CVE-2014-2420",
    "CVE-2014-2421",
    "CVE-2014-2423",
    "CVE-2014-2427",
    "CVE-2014-2428",
    "CVE-2014-3566"
  );
  script_bugtraq_id(
    63676,
    64493,
    65568,
    66856,
    66866,
    66870,
    66873,
    66879,
    66881,
    66883,
    66887,
    66891,
    66894,
    66898,
    66899,
    66902,
    66903,
    66904,
    66905,
    66907,
    66909,
    66910,
    66911,
    66914,
    66915,
    66916,
    66919,
    66920,
    67238,
    70574
  );
  script_xref(name:"CERT", value:"577193");

  script_name(english:"IBM Domino 9.0.x < 9.0.1 Fix Pack 2 Multiple Vulnerabilities (credentialed check) (POODLE)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has software installed that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Domino (formerly Lotus Domino) installed on the
remote host is 9.0.x prior to 9.0.1 Fix Pack 2 (FP2). It is,
therefore, affected by the following vulnerabilities :

  - An unspecified error exists related to the TLS
    implementation and the IBM HTTP server that could allow
    certain error cases to cause 100% CPU utilization. Note
    this issue only affects Microsoft Windows hosts.
    (CVE-2014-0963)

  - Fixes in the Oracle Java CPU for April 2014 are included
    in the fixed IBM Java release, which is included in the
    fixed IBM Domino release.
    (CVE-2013-6629, CVE-2013-6954, CVE-2014-0429,
    CVE-2014-0446, CVE-2014-0448, CVE-2014-0449,
    CVE-2014-0451, CVE-2014-0452, CVE-2014-0453,
    CVE-2014-0454, CVE-2014-0455, CVE-2014-0457,
    CVE-2014-0458, CVE-2014-0459, CVE-2014-0460,
    CVE-2014-0461, CVE-2014-1876, CVE-2014-2398,
    CVE-2014-2401, CVE-2014-2402, CVE-2014-2409,
    CVE-2014-2412, CVE-2014-2414, CVE-2014-2420,
    CVE-2014-2421, CVE-2014-2423, CVE-2014-2427,
    CVE-2014-2428)

  - A man-in-the-middle (MitM) information disclosure
    vulnerability, known as POODLE, exists due to the way
    SSL 3.0 handles padding bytes when decrypting messages
    encrypted using block ciphers in cipher block chaining
    (CBC) mode. A MitM attacker can decrypt a selected byte
    of a cipher text in as few as 256 tries if they are able
    to force a victim application to repeatedly send the
    same data over newly created SSL 3.0 connections.
    (CVE-2014-3566)");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21681114");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg24037141");
  # https://www.ibm.com/blogs/psirt/ibm-security-bulletin-ibm-notes-and-domino-multiple-vulnerabilities-in-ibm-java-oracle-april-2014-critical-patch-update-and-ibm-http-server-for-domino-cve-2014-0963/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb873351");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 9.0.1 FP2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-2421");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-3566");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("installed_sw/IBM Domino");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

appname = 'IBM Domino';
get_install_count(app_name:appname, exit_if_zero:TRUE);

port = get_kb_item('SMB/transport');
if (isnull(port)) port = 445;

install = get_single_install(app_name:appname);
domino_ver = install['version'];
path       = install['path'];
if (!empty_or_null(install['Java Version']))
  java_ver = install['Java Version'];
else
  audit(AUDIT_VER_FAIL, "jvm.dll");

# Fixed jvm.dll version
java_fix    = '2.4.2.65501';
domino_fix  = '9.0.1 FP2';

# Versions 9.0.x affected
if (
  domino_ver =~ "^9\.0($|[^0-9])" &&
  ver_compare(ver:java_ver, fix:java_fix, strict:FALSE) == -1
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Path                     : ' + path +
      '\n  Domino installed version : ' + domino_ver +
      '\n  JVM installed version    : ' + java_ver +
      '\n  JVM fixed version        : ' + java_fix + ' (included in Domino ' + domino_fix + ')' +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "IBM Domino's Java Virtual Machine", java_ver, path);
