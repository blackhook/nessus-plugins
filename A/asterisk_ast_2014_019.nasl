#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(80036);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2014-9374");
  script_bugtraq_id(71607);

  script_name(english:"Asterisk 'res_http_websocket' Double-Free DoS (AST-2014-019)");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to the version in its SIP banner, the version of Asterisk
running on the remote host is potentially affected by a double-free
error related to the 'res_http_websocket' module and handling of
zero-length payloads that could allow denial of service attacks.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2014-019.html");
  script_set_attribute(attribute:"see_also", value:"https://issues.asterisk.org/jira/browse/ASTERISK-24472");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 11.14.2 / 12.7.2 / 13.0.2 / 11.6-cert9 or apply
the appropriate patch listed in the Asterisk advisory.

Alternatively, as a workaround, disable the built-in HTTP server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-9374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/15");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("asterisk_detection.nasl");
  script_require_keys("asterisk/sip_detected", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("asterisk/sip_detected");

asterisk_kbs = get_kb_list_or_exit("sip/asterisk/*/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

is_vuln = FALSE;
not_vuln_installs = make_list();
errors = make_list();

foreach kb_name (keys(asterisk_kbs))
{
  vulnerable = 0;

  matches = eregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);
  if (isnull(matches))
  {
    errors = make_list(errors, "Unexpected error parsing port number from '"+kb_name+"'.");
    continue;
  }

  proto = matches[1];
  port  = matches[2];
  version = asterisk_kbs[kb_name];

  if (version == 'unknown')
  {
    errors = make_list(errors, "Unable to obtain version of install on " + proto + "/" + port + ".");
    continue;
  }

  banner = get_kb_item("sip/asterisk/" + proto + "/" + port + "/source");
  if (!banner)
  {
    # We have version but banner is missing;
    # log error and use in version-check though.
    errors = make_list(errors, "KB item 'sip/asterisk/" + proto + "/" + port + "/source' is missing.");
    banner = 'unknown';
  }

  # Open Source 11.x < 11.14.2
  if (version =~ "^11([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "11.14.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 12.x < 12.7.2
  else if (version =~ "^12([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "12.7.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Open Source 13.x < 13.0.2
  else if (version =~ "^13([^0-9]|$)" && "cert" >!< tolower(version))
  {
    fixed = "13.0.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  # Asterisk Certified 11.6-certx < 11.6-cert9
  else if (version =~ "^11\.6([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "11.6-cert9";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  if (vulnerable < 0)
  {
    is_vuln = TRUE;
    if (report_verbosity > 0)
    {
      report =
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_warning(port:port, proto:proto, extra:report);
    }
    else security_warning(port:port, proto:proto);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0)
  {
    if (is_vuln) exit(0);
    else audit(AUDIT_NOT_INST, "Asterisk");
  }
  else audit(AUDIT_INST_VER_NOT_VULN, "Asterisk", not_vuln_installs);
}
