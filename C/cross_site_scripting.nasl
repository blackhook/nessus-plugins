#TRUSTED 23cde73c5f3a11e7bffec8093f7f6c0f567609ab980bb736f04bfa7257638321cec0fe937884bc16eba94a109fdc38b1be26b583dae25978f6d49235b6d1d0c05cd7c617d4af6dedc9c310eed39c3adccfe4b447aba37fe077782942eabec36143194f3c7f9a244bfd7ca572ede3a90365946d8cac7d10c144b72c474be6a7f76484356f9b250d595c695187b9f01a54bcf31b194af5f7af2d889c674ba92585ae29bbe7316c04640abb2d516d7a45b02b6aeac985d5cce921fc968b854e4519799cd9584ae8d47685bdca725cf1e65bada47c2e8caaedbca5fdefea8e90bde9a217b62e448c42428860824b4288b82304ed984740e30b84af0eaadc8dd3ab75e8402d0027a625315a03a1072c79880457101ae0c82a1b5f023bb88ca5eaccb60dfd0acfc0d6bb38e1188744d7ae5f3d0ae4a9f5c24485a38bf38641befa66edde6155d9079db2906431e1ac338e92f1c32fafe56fdd7f69493a5a9d8dae8ef6ff5f19310f7a9c1940ded92e98dff96ee6edc733f3c0258a0286ef61830285720d9d7340edbb40601f892b35ce196e5c6a28eb396e80dc508dfb219fa3338fd4fecadf30fad8a2c56d1f90bcf4b4b044d3b37633f2dd77b688b1bf17bb1c3e921e4117498f4325540769119f21007c20fdcca51a7cef72ac01fb9527df5a87331d3ee1068f2e0eca27dfb5a98d5aef7c07d99cfd7d194f77e39f2d9d3f609b09
# 
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(10815);
  script_version("1.94");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/02");

  script_cve_id(
    "CVE-2002-1060",
    "CVE-2002-1700",
    "CVE-2003-1543",
    "CVE-2005-2453",
    "CVE-2006-1681",
    "CVE-2012-3382"
  );
  script_bugtraq_id(
    5011,
    5305,
    7344,
    7353,
    8037,
    14473,
    17408,
    54344
  );

  script_name(english:"Web Server Generic XSS");
  script_summary(english:"Checks for generic cross-site scripting vulnerability in a web server.");


  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a web server that fails to adequately
sanitize request strings of malicious JavaScript. A remote attacker
can exploit this issue, via a specially crafted request, to execute
arbitrary HTML and script code in a user's browser within the security
context of the affected site.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Cross-site_scripting");
  script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch or upgrade.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  # CVSSv3 score manually defined based on similar vuln (CVE-2021-42363)
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"); 
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2002-1060");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2001/11/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2005-2022 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include('http.inc');
include('string.inc');

##
# Check the content-type header to see if it is potentially vulnerable to XSS.
#   
#   content-type "text/*" AND not (text/html OR text/xml)
#   OR
#   content-type "application/*" AND not (application/xml)
#   OR
#   content-type "image/*" AND not (image/svg)
#   OR
#   content-type "audio/*"
#   OR
#   content-type "video/*"
# 
# @param ct The "Content-Type" header to check
# 
# @return TRUE if not a "xss" content-type, FALSE if not  
##
function non_xss_content_type(ct)
{
  if (left(ct,5) == 'text/' && !(right(ct,4) == 'html' || right(ct,3) == 'xml') || 
     (left(ct,12) == 'application/' && !(right(ct, 3) == 'xml')) ||
     (left(ct,6) == 'image/' && !(right(ct, 3) == 'svg')) ||
     (left(ct,6) == 'audio/') || 
     (left(ct,6) == 'video/'))
    return TRUE;  
  else
    return FALSE;
}

var port = get_http_port(default: 80, embedded: TRUE);

var file = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789");
var exts = make_list(
  "asp",
  "aspx",
  "pl",
  "cgi",
  "exe",
  "cfm",
  "html",
  "jsp",
  "php",
  "php3",
#  "phtml",
#  "shtml",
   "cfc",
   "nsf",
   "dll",
   "fts",
   "jspa",
   "kspx",
   "mscgi",
   "do",
   "htm",
   "idc",
   "x",
   ""
);

var exploits = make_list(
  # nb: while this isn't valid JavaScript, it will tell us
  #     if malicious script tags are output unfiltered.
  "<script>" + SCRIPT_NAME + "</script>",
  '<IMG SRC="javascript:alert(' + SCRIPT_NAME + ');">'
);

var hdrs = make_list(
  "Referer",
  "Cookie",
  "User-Agent",
  "Pragma",
  "Accept",
  "X-Forwarded-For",
  "Accept-Language",
  "Accept-Charset",
  "Expect",
  "Connection",
  "Host",
  "Content-Type",
  "Content-Length"
);

var vuln_url = FALSE;
var vuln_hdr = FALSE;

var vuln = 0;
var failures = 0;

var dirs_l = NULL;
var hdr_ext = NULL;
# If we are in paranoid mode, we want to reduce the FPs anyway.
if (thorough_tests) dirs_l = cgi_dirs();

if (isnull(dirs_l)) dirs_l = make_list("/");

var dir, len, ext, exploit, enc_exploit, url, ef, r, headers, rep_extra, non_vuln_headers, report;
foreach dir (dirs_l)
{
  len = strlen(dir);
  if (len == 0 || dir[0] != "/")
  {
    dir = "/" + dir;
    len ++;
  }
  if (len > 1 && dir[len-1] != "/") dir = dir + "/";

    foreach ext (exts)
    {
      foreach exploit (exploits)
      {
        if (" " >< exploit) enc_exploit = str_replace(find:" ", replace:"%20", string:exploit);
        else enc_exploit = exploit;

      if (ext)
        urls = make_list(
          dir + enc_exploit + "." + ext,
          dir + file + "." + ext + "?" + enc_exploit
        );
      else
        urls = make_list(
          # nb: does server check "filenames" for Javascript?
          dir + enc_exploit,
          enc_exploit,
          # nb: how about just the request string?
          dir + "?" + enc_exploit
        );

      foreach url (urls)
      {
        if (vuln_url) break;
        # Try to exploit the flaw.
        ef = (failures >= 2);
        r = http_send_recv3(method: 'GET', item:url, port:port, fetch404: TRUE, follow_redirect: 2, exit_on_fail: ef);
        if (isnull(r))
        {
          failures ++;
          continue;
        }

        headers = parse_http_headers(status_line:r[0], headers:r[1]);

        if (!empty_or_null(headers))
        {
          if (!empty_or_null(headers['content-disposition']) &&
              headers['content-disposition'] =~ 'attachment') continue;

          if (!empty_or_null(headers['content-type']))
          {
            if (headers['content-type'] !~ "text\/html")
            {
              rep_extra =
                'Note that this XSS attack may only work against ' +
                'web browsers\nthat have "content sniffing" enabled.';
            } 
          }
        }

        # call non_xss_content_type() for each Content-Type
        # some Content-Types are not vulnerable to XSS
        # we only want to flag if Content-Type is potentially vulnerable
        non_vuln_headers = non_xss_content_type(ct:headers['content-type']);

        if (exploit >< r[2])
        {
          # FP - content type not vulnerable
          if (r[0] =~ "^HTTP/1\.[01] 30[12] " || !non_vuln_headers) continue;	
          # FP - response body contains full URI (path), indicating an error
          if (url >< r[2]) continue;
          
          vuln++;

          report += crap(data:"-", length:30)+' Request #' + vuln + ' ' +crap(data:"-", length:30)+ '\n';
          report +=
            '\nThe request string used to detect this flaw was :\n\n' +
            url +
            '\n\nThe output was :\n\n' +
            r[0] + r[1] + '\n' +
            extract_pattern_from_resp(string: r[2], pattern: "ST:"+exploit)+
            '\n';
            if (rep_extra)
              report += rep_extra;

          vuln_url = TRUE;
          hdr_ext = ext;
        }
      }
    }
}

  # begin header tests
  if (thorough_tests)
  {
    var hdr, rq;
    foreach hdr (hdrs)
    {
      #build request
      if (empty_or_null(ext)) ext = "html";
      if (empty_or_null(hdr_ext)) hdr_ext = ext;
      exploit = "<script>alert(" + hdr + ")</script>";
      url = dir + file + "." + hdr_ext;
      rq = http_mk_req(item: url, port:port, method: "GET", add_headers: make_array(hdr, exploit));

      #send request
      r = http_send_recv_req(req: rq, port:port, fetch404: TRUE, only_content: "text/(xml|html)");
      if(isnull(r))
      {
        failures ++;
        continue;
      }

      #check response
      if (exploit >< r[2])
      {
        # FP - content type not vulnerable
        if (r[0] =~ "^HTTP/1\.[01] 30[12] " || !non_vuln_headers) continue;
        # FP - response body contains full URI (path), indicating an error
        if (url >< [r[2]]) continue; 

        vuln++;

        # report
        report += crap(data:"-", length:30)+' Request #' + vuln + ' ' +crap(data:"-", length:30)+ '\n';
        report += '\nThe full request used to detect this flaw was :\n\n' + 
          http_last_sent_request() +
          '\n\nThe output was :\n\n' +
          r[0] + r[1] + '\n' +
          extract_pattern_from_resp(string: r[2], pattern: "ST:"+exploit)+
          '\n';
      }
    }
  }
    # end header tests
}

if (vuln > 0)
{
  set_kb_item(name:'www/' + port + '/generic_xss', value:TRUE);
  security_report_v4(extra:report, port:port, severity:SECURITY_WARNING, xss:TRUE);
  exit(0);
}
exit(0, 'The web server listening on port ' +port+ ' is not affected.');
