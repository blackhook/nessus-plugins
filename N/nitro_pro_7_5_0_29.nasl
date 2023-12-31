#
# (C) Tenable network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66763);
  script_version("1.7");
  script_cvs_date("Date: 2019/12/04");

  script_cve_id("CVE-2013-3552");
  script_bugtraq_id(60180);
  script_xref(name:"MSVR", value:"MSVR13-006");

  script_name(english:"Nitro Pro <= 7.5.0.29 Memory Corruption");
  script_summary(english:"Checks version of Nitro Pro");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a PDF toolkit installed that is affected by a
memory corruption vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Nitro Pro installed on the remote Windows host is less
than or equal to 7.5.0.29 and is, therefore, reportedly affected by a
memory corruption vulnerability when parsing specially crafted PDF
files.");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Nitro Pro 8.0.1.19 / 8.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:nitropdf:nitro_pdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nitro_pro_installed.nasl");
  script_require_keys("SMB/Nitro Pro/installed");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

info = '';
info2 = '';
vuln = 0;
installs = get_kb_list("SMB/Nitro Pro/*/Path");
if (isnull(installs)) audit(AUDIT_KB_MISSING, 'SMB/Nitro Pro/*/Path');

vuln = 0;
foreach install (keys(installs))
{
  path = installs[install];
  version = install - 'SMB/Nitro Pro/' - '/Path';

  if (ver_compare(ver:version, fix:'7.5.0.29', strict:FALSE) <= 0)
  {
    info +=
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 8.0.1.19\n';
    vuln++;
  }
  else
    info2 += ' and ' + version;
}

if (vuln)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    if (vuln > 1) s = "s of Nitro Pro are";
    else s = " of Nitro Pro is";

    report =
      '\nThe following vulnerable instance' + s + ' installed on the' +
      '\nremote host :\n'+
      info;
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}

if (info2)
{
  info2 -= ' and ';
  if (' and ' >< info2) be = 'are';
  else be = 'is';

  exit(0, 'The host is not affected since Nitro Pro '+info2+' '+be+' installed.');
}
else exit(1, 'Unexpected error -  \'info2\' is empty.');
