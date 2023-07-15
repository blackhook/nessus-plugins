#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104042);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/04/11");

  script_cve_id("CVE-2017-14099", "CVE-2017-14603");
  script_bugtraq_id(100669, 101237);

  script_name(english:"Asterisk 11.x < 11.25.3 / 13.x < 13.17.2 / 14.x < 14.6.2 / 11.6 < 11.6-cert18 / 13.13 < 13.13-cert6 RTP/RTCP information leak (AST-2017-008)");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by 
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its SIP banner, the version of Asterisk running on the
remote host is 11.x prior to 11.25.3, 13.x prior to 13.17.2,
14.x prior to 14.6.2, 11.6 prior to 11.6-cert18, or 13.13 prior to
13.13-cert6. It is therefore, affected by an information disclosure
vulnerability due to insufficient RTCP packet validation. A remote
attacker could potentially read buffer contents and redirect where
the next RTCP report goes.

Note that Nessus has not tested for these issues but has instead
relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/AST-2017-008.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk version 11.25.3 / 13.17.2 / 14.6.2 / 11.6-cert18 / 13.13-cert6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14603");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/09/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  matches = pregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);
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
    errors = make_list(errors, "Unable to obtain version of installation on " + proto + "/" + port + ".");
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

  if (version =~ "^11([^0-9])" && "cert" >!< tolower(version))
  {
    fixed = "11.25.3";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^13([^0-9])" && "cert" >!< tolower(version))
  {
    fixed = "13.17.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^14([^0-9])" && "cert" >!< tolower(version))
  {
    fixed = "14.6.2";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^11\.6([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "11.6-cert18";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }
  else if (version =~ "^13\.13([^0-9])" && "cert" >< tolower(version))
  {
    fixed = "13.13-cert6";
    vulnerable = ver_compare(ver:version, fix:fixed, app:"asterisk");
  }

  if (vulnerable < 0)
  {
    is_vuln = TRUE;
    report =
        '\n  Version source    : ' + banner +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed +
        '\n';
      security_report_v4(severity:SECURITY_WARNING, port:port, proto:proto, extra:report);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installations : \n  ' + join(errors, sep:'\n  ');

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
