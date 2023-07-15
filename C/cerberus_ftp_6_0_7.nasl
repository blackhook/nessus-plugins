#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(73270);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_bugtraq_id(66322);

  script_name(english:"Cerberus FTP Server < 5.0.8.0 / 6.x < 6.0.7.0 Web Client Security Bypass");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server installed on the remote Windows host is potentially
affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cerberus FTP Server on the remote host is a version
prior to 5.0.8.0 or version 6.x prior to 6.0.7.0. As such, it is
potentially affected by a security bypass vulnerability.

An authenticated attacker could obtain sensitive files via the HTTP/S
interface.");
  script_set_attribute(attribute:"see_also", value:"https://www.cerberusftp.com/products/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cerberus FTP Server 5.0.8.0, 6.0.7.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"No CVE available: Information Disclosure");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2014-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cerberus_ftp_installed.nasl");
  script_require_keys("SMB/CerberusFTP/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/CerberusFTP/Installed");
installs = get_kb_list_or_exit("SMB/CerberusFTP/*/version");
kb_entry = branch(keys(installs));
kb_base = kb_entry - "/version";

ver  = get_kb_item_or_exit(kb_entry);
file_name = get_kb_item_or_exit(kb_base + "/file");

# Extract path from KB name
kb_pieces = split(kb_base, sep:"/");
file = kb_pieces[2] + "\" + file_name;

# Ensure Cerberus FTP Server HTTP/S is
# actually running if not paranoid
if (report_paranoia < 2)
{
  www_is_alive = FALSE;
  foreach item (make_list("active_http", "active_https"))
    if (get_kb_item("SMB/CerberusFTP/" + item)) www_is_alive = TRUE;

  if (!www_is_alive) exit(0, "The Cerberus FTP Server's Web Client does not appear to be enabled.");
}

fix = FALSE;

# 5.x and earlier
if (ver_compare(ver:ver, fix:'5.0.8.0', strict:FALSE) < 0)
  fix = '5.0.8.0';

# 6.x
if (ver =~ "^6\." && ver_compare(ver:ver, fix:'6.0.7.0', strict:FALSE) < 0)
  fix = '6.0.7.0';

if (fix)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n' +
      '\n  File              : ' + file +
      '\n  Installed version : ' + ver  +
      '\n  Fixed version     : ' + fix  +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Cerberus FTP Server", ver, file);
