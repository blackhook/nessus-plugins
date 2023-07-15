#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77026);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/09/20");

  script_bugtraq_id(69018);

  script_name(english:"Microsoft Exchange Client Access Server Information Disclosure");
  script_summary(english:"Attempts to get the server IP.");

  script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Exchange Client Access Server (CAS) is affected by an
information disclosure vulnerability. A remote, unauthenticated
attacker can exploit this vulnerability to learn the server's internal
IP address.
An attacker can send a crafted GET request to the Web Server with an 
empty host header that would expose internal IP Addresses of the 
underlying system in the header response.");
  script_set_attribute(attribute:"see_also", value:"http://foofus.net/?p=758");
  #https://docs.microsoft.com/en-us/archive/blogs/asiatech/why-private-ip-address-is-still-revealed-on-iis-server-even-after-applying-fix-834141
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4eedfe2d");
  script_set_attribute(attribute:"solution", value:"Only attack two (Reverse Proxy / Gateway) is fixed in current
versions. Apply the latest supplied vendor patches.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
   script_set_attribute(attribute:"cvss_score_rationale", value:"NVD score unavailable. Information disclosure vulnerability.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2018-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 443);
  exit(0);
}

include("http.inc");
include("network_func.inc");

# Make sure target host is an internet address.
if (is_private_addr()) audit(AUDIT_HOST_NOT, "Internet-accessible");

app_name = "Microsoft Exchange Client Access Server";
port = get_http_port(default:443);
ip = NULL;

urls_to_check = make_list(
  "/autodiscover/autodiscover.xml",
  "/microsoft-server-activesync/default.eas",
  "/ews/exchange.asmx");

ip_pattern = 'Basic realm="(\\d{1,3}(?:\\.\\d{1,3}){3})"';

foreach url (urls_to_check)
{
  clear_cookiejar();

  res = http_send_recv3(
    method       : "GET",
    item         : url,
    port         : port,
    version      : 10,
    exit_on_fail : TRUE);

  # Make sure we're looking at the right server.
  if ("Microsoft-IIS" >!< res[1] || "401" >!< res[0]) audit(AUDIT_NOT_LISTEN, app_name, port);

  # Parse the response for an IP and also ensure that it is an internal address.
  match = pregmatch(string:res[1], pattern:ip_pattern, icase:TRUE);
  if (!isnull(match) && is_private_addr(addr:match[1]))
  {
    ip = match[1];
    break;
  }
}

if (!isnull(ip))
{
  if (report_verbosity > 0)
  {
    report =
      '\n' + 'Nessus was able to verify the issue with the following request : ' +
      '\n' +
      '\n' + strip(http_last_sent_request()) +
      '\n' +
      '\n' + 'Which returned the following IP address :' +
      '\n' +
      '\n' + ip +
      '\n';

    security_warning(extra:report, port:port);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, app_name, port);
