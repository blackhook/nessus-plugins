#TRUSTED 246970634dfe6249c0072840297a617759795432b36662a89cbfe39bbb88a9676820bbcc346ac3afd11351a89b64ea3683b2902136bd0111ac2a4f639951fd54e713c64a6228a3ee895873a9186e73fac17a59199966f6d1e823c15844fb042a7513502cbc353523dd4895d97ccf1ee72cf24300ed281f58e679260f328281a579108c2b7c1f9884c147d08182d1e2019cdb7d76ee93b63a9312e94ee6d13a5178c6b1cbe448f54558c603806d720745cd45c1f9e487619d20eeef47f34ff0294806fd9ffde8f9da60cd6d1a1e18b29e84546ba104a003ba03fa6c9fa843a2ca80cb2d57ee2ba75bd35013bd2008aa6f5309c407ef148d13840fdd722fda85e00aa244321ae9f810f6e2abf9dd62eea54222c7c309593132115cb78b700dc8f1103f584ae98a4b4df18ed73d03108e425170d87026baf98afb68e7beaa59c492b3a677e9e17ac459a95c35c6c3320136db2a90af477fc1fa73494008c6e5fab271f6562ceab9d1c355d792ada8c766348f1d577caa3f00a99dd72b52dc2cccbd0839de37768a1840d0a2d3df5b002f0f72722b3079c9212743357d2a5297076c797ac302ab6aa8de5488a4cc119826ab5ac2b8868b5340d3859953d7c834050e9a7089d557d1f33805a7af739d9eb50640af87039d85e89f58670600e889f666b47d88fb858dc0873b0f789b71d7b7dc758d0a2c8850c45d73a1956dadc4e883
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(92539);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id(
    "CVE-2016-5385",
    "CVE-2016-5386",
    "CVE-2016-5387",
    "CVE-2016-5388",
    "CVE-2016-1000109",
    "CVE-2016-1000110"
  );
  script_bugtraq_id(
    91815,
    91816,
    91818,
    91821
  );
  script_xref(name:"CERT", value:"797896");

  script_name(english:"HTTP_PROXY Environment Variable Namespace Collision Vulnerability (httpoxy)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application is affected by a man-in-the-middle
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The web application running on the remote web server is affected by a
man-in-the-middle vulnerability known as 'httpoxy' due to a failure to
properly resolve namespace conflicts in accordance with RFC 3875
section 4.1.18. The HTTP_PROXY environment variable is set based on
untrusted user data in the 'Proxy' header of HTTP requests. The
HTTP_PROXY environment variable is used by some web client libraries
to specify a remote proxy server. An unauthenticated, remote attacker
can exploit this, via a crafted 'Proxy' header in an HTTP request, to
redirect an application's internal HTTP traffic to an arbitrary proxy
server where it may be observed or manipulated.");
  script_set_attribute(attribute:"see_also", value:"https://httpoxy.org/");
  script_set_attribute(attribute:"see_also", value:"https://seclists.org/oss-sec/2016/q3/94");
  script_set_attribute(attribute:"solution", value:
"Applicable libraries and products should be updated to address this
vulnerability. Please consult the library or product vendor for
available updates.

If updating the libraries and products is not an option, or if updates
are unavailable, filter 'Proxy' request headers on all inbound
requests.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-5386");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:php:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:golang:go");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:drupal:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:facebook:hiphop_virtual_machine");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2016-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("webmirror.nasl");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");
include("http.inc");

port = get_http_port(default: 80);

urls = make_list();

# Fix for webmirror_uri "no such table" errors
table = query_scratchpad("SELECT name FROM sqlite_master where type = 'table' and name = 'webmirror_uri'");
if (empty_or_null(table)) exit(1, "Unable to obtain webmirror_uri table from webmirror crawl.");

# Query Scratchpad for webmirror results with a status code of 200
# and load results into urls list
res = query_scratchpad("SELECT DISTINCT uri FROM webmirror_uri WHERE port = ? AND status_code = 200 ORDER BY uri ASC", port);
if (empty_or_null(res)) exit(1, 'Unable to obtain crawled URIs from webmirror scratchpad.');

# Loop through filters to discard URLs we don't care about testing
i = 0;
foreach url (res)
{
  if (
       # Filter out Apache directory listings page sorting
       url['uri'] !~ "/\?[CO]\=[NDMSA](%|$)" &&
       # Filter out static text files
       url['uri'] !~ "\.(md|js|css|scss|txt|csv|xml)($|\?)" &&
       # Filter out image files
       url['uri'] !~ "\.(gif|jpeg|jpg|png|svg|ttf|eot|woff|ico)($|\?)" &&
       # Filter out binary files
       url['uri'] !~ "\.(exe|zip|gz|tar)($|\?)" &&
       # Filter out document files
       url['uri'] !~ "\.(rtf|doc|docx|pdf|xls|xlt)($|\?)"
     )
  {
    # Strip any trailing args from URLs to get the url count down
    if ("?" >< url['uri'])
      url['uri'] = ereg_replace(pattern:"(.*)\?.*", replace:"\1", string:url['uri']);

    urls = make_list(urls, url['uri']);
    i++;
  }
  # If thorough_tests is not enabled, stop at 10 urls
  if (!thorough_tests && i > 10) break;
}

# If we have no URLs to check, bail out
if (empty_or_null(urls))
  audit(AUDIT_WEB_FILES_NOT, "dynamic content", port);

urls = list_uniq(urls);
scanner_ip = compat::this_host();
target_ip = get_host_ip();
pat = "HTTP/1\.(0|1)";
vuln = FALSE;

foreach url (urls)
{
  # If we get an empty url string, just go to the next
  if(empty_or_null(url)) continue;
  listener = bind_sock_tcp();
  if (!listener) audit(AUDIT_SOCK_FAIL, 'tcp', 'unknown');

  s_port = listener[1];
  s = listener[0];

  # Exploit is scanner's IP and our listener's socket in the Proxy header
  exploit = scanner_ip + ':' + s_port;
  v = http_mk_get_req(port: port, item: url, add_headers: make_array("Proxy", exploit));
  req = http_mk_buffer_from_req(req: v);
  # We don't need to check the response we get back from the request's socket
  req = http_send_recv_buf(port:port, data:req);

  # When we have a successful attack, we won't get a response returned
  # to req, since the proxied request causes the server-side script to
  # pause execution and timeout without a response. Since we check for
  # NULL here, we can bypass the listener socket timeout for non-vuln
  # URLs to process through the URL queue faster.
  if(isnull(req))
  {
    # Instead we're more interested in if we get data on the listener socket
    soc = sock_accept(socket:s, timeout:3);
    res = recv(socket:soc, length:1024, timeout:3);
    close(s);
  }
  else
  {
    res = NULL;
    close(s);
  }

  if (!empty_or_null(res) && (res =~ pat))
  {
    vuln = TRUE;
    report = '\nThe full request used to detect this flaw was :\n\n' +
      http_last_sent_request() +
      '\n\nThe server sent back the following data to the listener on port ' + s_port + ':\n\n' +
      res +
      '\n';
  }

  # Stop after first vulnerable page is found
  if (vuln) break;
}

if (vuln)
{
  security_report_v4(
    port       : port,
    severity   : SECURITY_WARNING,
    extra      : report
  );
  exit(0);
}
audit(AUDIT_WEB_SERVER_NOT_AFFECTED, port);
