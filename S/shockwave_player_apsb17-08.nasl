#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97835);
  script_version("1.6");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-2983");
  script_bugtraq_id(96863);

  script_name(english:"Adobe Shockwave Player <= 12.2.7.197 DLL Hijacking (APSB17-08)");
  script_summary(english:"Checks the version of Shockwave Player.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser plugin that is affected
by a DLL hijacking vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host contains a version of Adobe Shockwave Player
that is prior or equal to 12.2.7.197. It is, therefore, affected by a
DLL hijacking vulnerability when loading certain dynamic link library
(DLL) files due to searching an insecure path that may not be trusted
or under user control. An unauthenticated, remote attacker can exploit
this issue to execute arbitrary code, with the privileges of the user
running the program, by placing a specially crafted file in the path
and convincing the user to open a supported file type (e.g., located
on a remote WebDAV share).");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/shockwave/apsb17-08.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Shockwave Player version 12.2.8.198 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2983");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:shockwave_player");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("shockwave_player_apsb09_08.nasl");
  script_require_keys("SMB/shockwave_player");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list_or_exit("SMB/shockwave_player/*/path");

appname = "Shockwave Player";

latest_vuln_version = "12.2.7.197"; # versions <= this version are vuln
fix = "12.2.8.198";

info = NULL;
pattern = "SMB/shockwave_player/([^/]+)/([^/]+)/path";

vuln = 0;
foreach install (keys(installs))
{
  match = eregmatch(string:install, pattern:pattern);
  if (!match) exit(1, "Unexpected format of KB key '" + install + "'.");

  file = installs[install];
  variant = match[1];
  version = match[2];

  if (ver_compare(ver:version, fix:latest_vuln_version) <= 0)
  {
    if (variant == "Plugin")
      info += '\n  Variant           : Browser Plugin (for Firefox / Netscape / Opera)';
    else if (variant == "ActiveX")
      info += '\n  Variant           : ActiveX control (for Internet Explorer)';
    info +=
      '\n  File              : ' + file +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    vuln++;
  }
}

if (!info) audit(AUDIT_INST_VER_NOT_VULN, appname);

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0)
{
  if (vuln > 1) s = "s";
  else s = "";

  report =
    '\n' + 'Nessus has identified the following vulnerable instance' + s + ' of Shockwave'+
    '\n' + 'Player installed on the remote host :' +
    '\n' +
    info + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);

