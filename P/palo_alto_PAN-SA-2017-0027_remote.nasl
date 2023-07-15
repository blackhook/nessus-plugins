#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(105376);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/19");

  script_cve_id("CVE-2017-15944");
  script_bugtraq_id(102079);
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/09/08");

  script_name(english:"Palo Alto Networks PAN-OS Management Interface RCE (PAN-SA-2017-0027)");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Palo Alto Networks PAN-OS running on the remote host is affected
by a remote code execution vulnerability in the management interface
due to improper validation of user-supplied input when handling HTTP 
requests. An unauthenticated, remote attacker can exploit this, via
a series of specially crafted requests, to cause remote code
execution in the context of the highest privileged user. 

Note that PAN-OS is reportedly affected by other vulnerabilities as
well; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/102");
  # https://packetstormsecurity.com/files/145396/Palo-Alto-Networks-Firewalls-Remote-Root-Code-Execution.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d516b278");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 6.1.19 / 7.0.19 / 7.1.14
/ 8.0.6 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-15944");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Palo Alto Networks readSessionVarsFromFile() Session Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_webui_detect.nbin");
  script_require_keys("www/palo_alto_panos");
  script_require_ports("Services/www", 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("http.inc");

app = 'palo_alto_panos';

# Exit if PAN-OS is not detected on the target host
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:443, embedded:TRUE);

# Exit if PAN-OS is not detected on this port
install = get_single_install(app_name:app, port: port);

# The 'device' parameter contains an invalid char for
# the patched cms_changeDeviceContext.php.
# So the patched php script will return a different response
# than the vulnerable one.
#
# This 'device' parameter specifically causes the vulnerable server
# to return 'Invalid device location string'.
url = '/esp/cms_changeDeviceContext.esp?device=8@foo:';
res = http_send_recv3(
  method:'GET',
  item:url,
  port:port,
  exit_on_fail:TRUE
);

if(empty_or_null(res[2]))
{
  audit(AUDIT_RESP_BAD, port, "a 'cms_changeDeviceContext' request:" + ' No data in the HTTP response body.');
}

# Patched
# Validation in cms_changeDeviceContext.php fails the 'device' string.
# panmodule.so!panUserSetDeviceLocation() is not called.
# So empty string btw the second and third @s.
if('@start@@end@' >< res[2])
{
  audit(AUDIT_WEB_APP_NOT_AFFECTED, 'Palo Alto PAN-OS', build_url(qs:install['path'], port:port));
}
# Vulnerable
# cms_changeDeviceContext.php does not check the 'device' string.
# panmodule.so!panUserSetDeviceLocation() is called.
# panUserSetDeviceLocation() returns "Invalid device location string"
# So the vulnerable server would respond something like:
#
# @start@Invalid device location string: 8@foo:
# @end@
else if('Invalid device location string' >< res[2])
{
  extra = 'Nessus was able to detect the issue with the following request :\n\n' + http_last_sent_request();

  security_report_v4(
    port       : port,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
}
# Unexpected response
else
{
  audit(AUDIT_RESP_BAD, port, "a 'cms_changeDeviceContext' request." + ' Unexpected HTTP response body:\n' + res[2]);
}
