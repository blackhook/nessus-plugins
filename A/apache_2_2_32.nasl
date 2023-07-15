#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96450);
  script_version("1.9");
  script_cvs_date("Date: 2019/03/27 13:17:50");

  script_cve_id("CVE-2016-4975", "CVE-2016-5387", "CVE-2016-8743");
  script_bugtraq_id(91816, 95077, 105093);
  script_xref(name:"CERT", value:"797896");

  script_name(english:"Apache 2.2.x < 2.2.32 Multiple Vulnerabilities (httpoxy)");
  script_summary(english:"Checks the version in the server response header.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of Apache running on the remote
host is 2.2.x prior to 2.2.32. It is, therefore, affected by the
following vulnerabilities :

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

  - A flaw exists due to improper handling of whitespace
    patterns in user-agent headers. An unauthenticated,
    remote attacker can exploit this, via a specially
    crafted user-agent header, to cause the program to
    incorrectly process sequences of requests, resulting in
    interpreting responses incorrectly, polluting the cache,
    or disclosing the content from one request to a second
    downstream user-agent. (CVE-2016-8743)

  - A CRLF injection allowing HTTP response splitting attacks for
    sites which use mod_userdir (CVE-2016-4975)

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://httpd.apache.org/dev/dist/Announcement2.2.html");
  script_set_attribute(attribute:"see_also", value:"http://httpd.apache.org/security/vulnerabilities_22.html");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apache/httpd/blob/2.2.x/CHANGES");
  script_set_attribute(attribute:"see_also", value:"https://www.apache.org/security/asf-httpoxy-response.txt");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache version 2.2.32 or later.

Note that the 'httpoxy' vulnerability can be mitigated by applying the
workarounds or patches as referenced in the vendor advisory
asf-httpoxy-response.txt.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5387");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/12");


  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2004-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("apache_http_version.nasl");
  script_require_keys("installed_sw/Apache", "Settings/ParanoidReport");
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

constraints = [
  { "min_version" : "2.2.0", "fixed_version" : "2.2.32"  }

];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
