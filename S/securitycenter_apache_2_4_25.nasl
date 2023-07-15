#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101044);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/09");

  script_cve_id(
    "CVE-2016-0736",
    "CVE-2016-2161",
    "CVE-2016-5387",
    "CVE-2016-8740",
    "CVE-2016-8743"
  );
  script_bugtraq_id(
    91816,
    94650,
    95076,
    95077,
    95078
  );
  script_xref(name:"CERT", value:"797896");
  script_xref(name:"EDB-ID", value:"40961");

  script_name(english:"Tenable SecurityCenter Apache 2.4.x < 2.4.25 Multiple Vulnerabilities (TNS-2017-04) (httpoxy)");
  script_summary(english:"Checks the version of Apache in SecurityCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The Tenable SecurityCenter application on the remote host contains a
web server that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Tenable SecurityCenter application installed on the remote host
is missing a security patch. It is, therefore, affected by multiple
vulnerabilities in the bundled version of Apache :

  - A flaw exists in the mod_session_crypto module due to
    encryption for data and cookies using the configured
    ciphers with possibly either CBC or ECB modes of
    operation (AES256-CBC by default). An unauthenticated,
    remote attacker can exploit this, via a padding oracle
    attack, to decrypt information without knowledge of the
    encryption key, resulting in the disclosure of
    potentially sensitive information. (CVE-2016-0736)

  - A denial of service vulnerability exists in the
    mod_auth_digest module during client entry allocation.
    An unauthenticated, remote attacker can exploit this,
    via specially crafted input, to exhaust shared memory
    resources, resulting in a server crash. (CVE-2016-2161)

  - The Apache HTTP Server is affected by a
    man-in-the-middle vulnerability known as 'httpoxy' due
    to a failure to properly resolve namespace conflicts in
    accordance with RFC 3875 section 4.1.18. The HTTP_PROXY
    environment variable is set based on untrusted user data
    in the 'Proxy' header of HTTP requests. The HTTP_PROXY
    environment variable is used by some web client
    libraries to specify a remote proxy server. An
    unauthenticated, remote attacker can exploit this, via a
    crafted 'Proxy' header in an HTTP request, to redirect
    an application's internal HTTP traffic to an arbitrary
    proxy server where it may be observed or manipulated.
    (CVE-2016-5387)

  - A denial of service vulnerability exists in the
    mod_http2 module due to improper handling of the
    LimitRequestFields directive. An unauthenticated, remote
    attacker can exploit this, via specially crafted
    CONTINUATION frames in an HTTP/2 request, to inject
    unlimited request headers into the server, resulting in
    the exhaustion of memory resources. (CVE-2016-8740)

  - A flaw exists due to improper handling of whitespace
    patterns in user-agent headers. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted user-agent header, to cause the program to
    incorrectly process sequences of requests, resulting in
    interpreting responses incorrectly, polluting the cache,
    or disclosing the content from one request to a second
    downstream user-agent. (CVE-2016-8743)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2017-04");
  script_set_attribute(attribute:"see_also", value:"https://static.tenable.com/prod_docs/upgrade_security_center.html");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_24.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable SecurityCenter version 5.4.3 or later.
Alternatively, contact the vendor for a patch.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/26");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:securitycenter");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("securitycenter_installed.nbin", "securitycenter_detect.nbin");
  script_require_ports("Host/SecurityCenter/Version", "installed_sw/SecurityCenter", "Host/SecurityCenter/support/httpd/version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Apache (within SecurityCenter)";
fix = "2.4.25";

sc_ver = get_kb_item("Host/SecurityCenter/Version");
port = 0;
if(empty_or_null(sc_ver))
{
  port = 443;
  install = get_single_install(app_name:"SecurityCenter", combined:TRUE, exit_if_unknown_ver:TRUE);
  sc_ver = install["version"];
}
if (empty_or_null(sc_ver)) audit(AUDIT_NOT_INST, "SecurityCenter");

version = get_kb_item("Host/SecurityCenter/support/httpd/version");
if (empty_or_null(version)) audit(AUDIT_UNKNOWN_APP_VER, app);

if (ver_compare(ver:version, minver:"2.3", fix:fix, strict:FALSE) < 0)
{
  report =
    '\n  SecurityCenter version         : ' + sc_ver +
    '\n  SecurityCenter Apache version  : ' + version +
    '\n  Fixed Apache version           : ' + fix +
    '\n';
  security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, version);
