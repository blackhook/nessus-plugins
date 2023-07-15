#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(172440);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/15");

  script_cve_id("CVE-2023-1101");

  script_name(english:"SonicWall SonicOS Security Misconfiguration (SNWLID-2023-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security misconfiguration vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote SonicWall firewall is running a version of SonicOS that is affected
by a security misconfiguration vulnerability, due to improper restriction of excessive MFA attempts in the SonicOS
SSLVPN interface, which may allow a remote authenticated attacker to use excessive MFA codes.

Note that Nessus has not tested for these issues but has instead relied only on the firewall's self-reported version
number.");
  # https://psirt.global.sonicwall.com/vuln-detail/SNWLID-2023-0005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c99da51");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1101");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/03/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:sonicwall:sonicos");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:sonicwall:nsv");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "sonicwall_nsv_ssl_vpn_web_detect.nbin");
  script_require_keys("Host/OS");

  exit(0);
}

var os = get_kb_item_or_exit('Host/OS');
if (os !~ "^SonicOS" ) audit(AUDIT_OS_NOT, 'SonicWall SonicOS');

include('vcf.inc');

var sslvpn_app = get_single_install(
  app_name:'SonicWall NSv Next-Gen Virtual Firewall SSL VPN',
  exit_if_unknown_ver:FALSE, combined:TRUE);
  
var sslvpn_status = sslvpn_app['SSLVPN Status'];
if (empty_or_null(sslvpn_status) || sslvpn_status != "enabled")
  audit(AUDIT_OS_CONF_NOT_VULN, "SonicWall");

# SonicOSX 7.0.1-1282-5db19878 on a SonicWALL NSv 270
var match = pregmatch(pattern:"^SonicOS.* ([0-9.]+)(?:(?:-)([0-9]*).*)? on a SonicWALL (.*)$", string:os);
if (empty_or_null(match)) exit(1, 'Failed to identify the version of SonicOS.');
var version = match[1];
var ext = match[2];
var model = match[3];

var full_ver;
if (!empty_or_null(ext))
{
  full_ver = version + '-' + ext;
}
else
{
  full_ver = version;
  ext = 0; 
}

var fix = NULL;

# not checking 6.5.4.4-44v-21-1551 and earlier versions for NSv 10, 25, 50, 100, 200, 300, 400, 800, 1600
# vuln: 7.0.1-5095 and earlier versions for NSv 270, 470, 870 - fixed: 7.0.1-5111 and higher
if (model =~ 'NSv (2|4|8)70' && (
  (version =~ "7\.0\.0") || (version =~ "7\.0\.1([^0-9]|$)" && (ver_compare(ver:ext, fix:'5095', strict:FALSE) <= 0))))
    fix = '7.0.1-5111 and higher';

if (empty_or_null(fix))
  audit(AUDIT_DEVICE_NOT_VULN, 'SonicWall ' + model, 'SonicOS ' + full_ver);

var port = 0;
var report =
  '\n  Installed SonicOS version : ' + full_ver +
  '\n  Fixed SonicOS version     : ' + fix +
  '\n';

security_report_v4(port:port, extra:report, severity:SECURITY_HOLE);