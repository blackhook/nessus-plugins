#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(47588);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/16");

  script_cve_id("CVE-2004-2769");
  script_bugtraq_id(41285);
  script_xref(name:"Secunia", value:"40370");

  script_name(english:"Cerberus FTP Server MLSD and MLST Command Hidden Files Security Bypass");
  script_summary(english:"Does a version check");

  script_set_attribute(attribute:"synopsis", value:
"The FTP server installed on the remote Windows host has a security
bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Cerberus FTP server on the remote host is earlier than
4.0.3.0.  Such versions are potentially affected by a security bypass
vulnerability.  The 'MLSD' and 'MLST' commands list hidden files despite
the 'Display hidden files' option being disabled.  A remote attacker,
possibly uncredentialed, may be able to leverage this issue to enumerate
hidden files on the affected system.");
  script_set_attribute(attribute:"see_also", value:"https://www.cerberusftp.com/phpBB3/viewtopic.php?f=4&t=644");
  script_set_attribute(attribute:"see_also", value:"https://www.cerberusftp.com/products/releasenotes/");
  script_set_attribute(attribute:"solution", value:"Upgrade to Cerberus FTP server 4.0.3 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2004-2769");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cerberusftp:ftp_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2010-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cerberus_ftp_installed.nasl");
  script_require_keys("SMB/CerberusFTP/Installed");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

installs = get_kb_list("SMB/CerberusFTP/*/version");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Cerberus FTP");

fixed = '4.0.3.0';

info = "";
not_vuln_installs = make_list();

foreach install (keys(installs))
{
  ver = installs[install];
  path = (install - "/version") - "SMB/CerberusFTP/";;

  if (ver_compare(ver:ver, fix:fixed) < 0)
  {
    info +=
      '\n' +
      '\n  Path              : ' + path  +
      '\n  Installed version : ' + ver   +
      '\n  Fixed version     : ' + fixed +
      '\n';
  }
  else not_vuln_installs = make_list(not_vuln_installs, ver + " under " + path);
}

if (vuln_found)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0) security_warning(port:port, extra:info);
  else security_warning(port);

  exit(0);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0) audit(AUDIT_NOT_INST, "Cerberus FTP");
  else if (installs == 1) audit(AUDIT_INST_VER_NOT_VULN, "Cerberus FTP " + not_vuln_installs[0]);
  else exit(0, "The Cerberus FTP installs (" + join(not_vuln_installs, sep:", ") + ") are not affected.");
}
