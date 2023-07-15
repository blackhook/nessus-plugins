#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(103052);
  script_version("1.3");
  script_cvs_date("Date: 2019/11/12");

  script_cve_id("CVE-2017-11455");
  script_bugtraq_id(100530);

  script_name(english:"Pulse Connect Secure Cross-Site Request Forgery (SA40793)");
  script_summary(english:"Checks PCS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Pluse Connect
Secure running on the remote host is affected by a cross-site request
forgery vulnerability in diag.cgi. This vulnerability may allow
remote attackers to hijack the authentication of administrators for
requests to start tcpdump.");
  # https://kb.pulsesecure.net/articles/Pulse_Security_Advisories/SA40793
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c8352c00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to  or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-11455");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:ive_os");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_secure_access_service");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:juniper:junos_pulse_access_control_service");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Juniper/IVE OS/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('Host/Juniper/IVE OS/Version');
match = eregmatch(string:version, pattern:"^([0-9.]+)[Rr]([0-9.]+)");
if (isnull(match)) exit(1, 'Error parsing version: ' + version);

release = match[1];
build   = match[2];

# Pulse Connect Secure
if (release == '8.3' && ver_compare(ver:build, fix:'1', strict:FALSE) == -1)
  fix = '8.3R1';
else if (release == '8.2' && ver_compare(ver:build, fix:'6', strict:FALSE) == -1)
  fix = '8.2R6';
else if (release == '8.1' && ver_compare(ver:build, fix:'12', strict:FALSE) == -1)
  fix = '8.1R12';
else if (release == '8.0' && ver_compare(ver:build, fix:'17', strict:FALSE) == -1)
  fix = '8.0R17';
# Not affected
else
  audit(AUDIT_INST_VER_NOT_VULN, 'Pulse Connect Secure', version);

report =
  '\nThe version of Pulse Connect Secure is vulnerable:' +
  '\n  Installed version : ' + version +
  '\n  Fixed version     : ' + fix + '\n';
security_report_v4(port:0, extra:report, severity:SECURITY_WARNING, xsrf:TRUE);
