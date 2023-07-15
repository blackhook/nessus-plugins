#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(101787);
  script_version("1.12");
  script_cvs_date("Date: 2018/09/17 21:46:53");

  script_cve_id(
    "CVE-2017-3167",
    "CVE-2017-3169",
    "CVE-2017-7668",
    "CVE-2017-7679",
    "CVE-2017-9788"
  );
  script_bugtraq_id(
    99134,
    99135,
    99137,
    99170,
    99569
  );

  script_name(english:"Apache 2.2.x < 2.2.34 Multiple Vulnerabilities");
  script_summary(english:"Checks version in Server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.2.x prior to 2.2.34. It is, therefore, affected by the
following vulnerabilities :

  - An authentication bypass vulnerability exists in httpd
    due to third-party modules using the
    ap_get_basic_auth_pw() function outside of the
    authentication phase. An unauthenticated, remote
    attacker can exploit this to bypass authentication
    requirements. (CVE-2017-3167)

  - A denial of service vulnerability exists in httpd due to
    a NULL pointer dereference flaw that is triggered when a
    third-party module calls the mod_ssl
    ap_hook_process_connection() function during an HTTP
    request to an HTTPS port. An unauthenticated, remote
    attacker can exploit this to cause a denial of service
    condition. (CVE-2017-3169)

  - A denial of service vulnerability exists in httpd due to
    an out-of-bounds read error in the ap_find_token()
    function that is triggered when handling a specially
    crafted request header sequence. An unauthenticated,
    remote attacker can exploit this to crash the
    service or force ap_find_token() to return an incorrect
    value. (CVE-2017-7668)

  - A denial of service vulnerability exists in httpd due to
    an out-of-bounds read error in the mod_mime that is
    triggered when handling a specially crafted Content-Type
    response header. An unauthenticated, remote attacker can
    exploit this to disclose sensitive information or cause
    a denial of service condition. (CVE-2017-7679)

  - A denial of service vulnerability exists in httpd due to
    a failure to initialize or reset the value placeholder
    in [Proxy-]Authorization headers of type 'Digest' before
    or between successive key=value assignments by
    mod_auth_digest. An unauthenticated, remote attacker can
    exploit this, by providing an initial key with no '='
    assignment, to disclose sensitive information or cause a
    denial of service condition. (CVE-2017-9788)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://archive.apache.org/dist/httpd/CHANGES_2.2.34");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.34 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3167");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/07/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:httpd");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2017-2018 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("vcf.inc");
include("http.inc");

port = get_http_port(default:80);
kb_base = "www/apache/"+port+"/";
kb_ver = NULL;
kb_backport = NULL;
kb_source = NULL;

if (get_kb_item(kb_base+"version")) kb_ver = kb_base+"version";
if (get_kb_item(kb_base+"backported")) kb_backport = kb_base+"backported";
if (get_kb_item(kb_base+"source")) kb_source = kb_base+"source";

app_info = vcf::get_app_info(
  app:"Apache",
  port:port,
  kb_ver:kb_ver,
  kb_backport:kb_backport,
  kb_source:kb_source,
  service:TRUE
);

vcf::check_granularity(app_info:app_info, sig_segments:3);

# 2.2.34
constraints = [
  { "min_version" : "2.2", "fixed_version" : "2.2.34" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
