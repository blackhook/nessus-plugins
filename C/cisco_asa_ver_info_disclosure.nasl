#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91964);
  script_version("1.8");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2014-3398");
  script_bugtraq_id(70230);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq65542");

  script_name(english:"Cisco ASA SSL VPN Functionality Version Information Disclosure (CSCuq65542)");
  script_summary(english:"Attempts to get the device version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its version and configuration, the Cisco Adaptive
Security Appliance (ASA) software on the remote device is affected by
an information disclosure vulnerability in the SSL VPN feature due to
improperly returning verbose response data. An unauthenticated, remote
attacker can exploit this, by requesting a specific URL
(/CSCOSSLC/config-auth) via HTTPS, to disclose the software version
information.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=35946
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?90ac6b01");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35946");
  # http://carnal0wnage.attackresearch.com/2015/02/cisco-asa-version-grabber-cve-2014-3398.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5013fbe");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco bug ID CSCuq65542.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/06");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_asa_ssl_vpn_detect.nasl");
  script_require_keys("Services/cisco-ssl-vpn-svr");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

appname = "Cisco ASA";
port    = get_service(svc:"cisco-ssl-vpn-svr", default:443, exit_on_fail:TRUE);

url     = "/CSCOSSLC/config-auth";
version = UNKNOWN_VER;

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail:TRUE);

if (res[0] =~ "^HTTP/[0-9.]+ +200" && "<config-auth client=" >< res[2])
{
  # Example: <version who="sg">9.1(5)</version>
  pat = "<version [^>]+>([0-9.]+\([0-9.]+\)\d{0,2})</version>";

  matches = eregmatch(pattern:pat, string:res[2]);
  if (!isnull(matches))
  {
    version = matches[1]; 

    report = 
      '\n' + "Nessus was able to determine the remote Cisco ASA version :" +
      '\n' +
      '\n' + "  URL     : " + build_url(port:port, qs:url) + 
      '\n' + "  Version : " + version +
      '\n';
    security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  }
  else audit(AUDIT_DEVICE_NOT_VULN, "The "+appname+" on port "+port);
}
else audit(AUDIT_DEVICE_NOT_VULN, "The "+appname+" on port "+port);
