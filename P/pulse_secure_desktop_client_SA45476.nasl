#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166980);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/06/22");

  script_cve_id("CVE-2022-21826");
  script_xref(name:"IAVA", value:"2022-A-0459-S");

  script_name(english:"Pulse Secure Desktop Client < 9.1R16 Client Side Desync (SA45476)");

  script_set_attribute(attribute:"synopsis", value:
"A VPN client installed on the remote host is affected by a client side desync vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Pulse Secure Desktop Client installed on the remote host is prior to 9.1R16. It is, therefore, affected 
by client-side http request smuggling. When the application receives a POST request, it ignores the request's 
Content-Length header and leaves the POST body on the TCP/TLS socket. This body ends up prefixing the next HTTP request
sent down that connection, this means when someone loads website attacker may be able to make browser issue a POST to 
the application, enabling XSS.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://kb.pulsesecure.net/articles/Pulse_Secure_Article/Client-Side-Desync-Attack-Informational-Article/?kA13Z000000FsZz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?da57d3b2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Pulse Secure Desktop Client 9.1R16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21826");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pulsesecure:pulse_secure_desktop_client");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("pulse_connect_secure_detect.nbin");
  script_require_keys("installed_sw/Pulse Connect Secure");

  exit(0);
}

include('http.inc');
include('vcf.inc');
include('vcf_extras.inc');

var port = get_http_port(default:443, embedded:TRUE);
var app_info = vcf::pulse_connect_secure::get_app_info(app:'Pulse Connect Secure', port:port, full_version:TRUE, webapp:TRUE);

# full ver from https://help.ivanti.com/ps/help/en_US/ICS/9.1RX/9.1R16-ICS-ReleaseNotes.pdf
var constraints = [
  {'fixed_version':'9.1.16.0', 'fixed_display':'9.1R16'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, flags:{'xss':TRUE}, severity:SECURITY_WARNING);
