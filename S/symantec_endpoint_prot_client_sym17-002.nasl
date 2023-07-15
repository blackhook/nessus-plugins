#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97661);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2016-9093");
  script_bugtraq_id(96294);

  script_name(english:"Symantec Endpoint Protection Client 12.1.x < 12.1 RU6 MP7 Local Privilege Escalation (SYM17-002)");
  script_summary(english:"Checks the SEP Client version.");

  script_set_attribute(attribute:"synopsis", value:
"The Symantec Endpoint Protection Client installed on the remote host
is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection (SEP) Client installed on
the remote host is 12.1.x prior to 12.1 RU6 MP7. It is, therefore,
affected by a local privilege escalation vulnerability in the SymEvent
driver due to improper validation of user-supplied input. A local
attacker can exploit this, via a specially crafted file, to manipulate
certain system calls, resulting in a denial of service condition, or
on 64-bit machines only, the possible execution of arbitrary code with
kernel-level privileges.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://support.symantec.com/en_US/article.SYMSA1398.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?314e9662");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Client version 12.1 RU6 MP7
or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-9093");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("savce_installed.nasl");
  script_require_keys("Antivirus/SAVCE/version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app = 'Symantec Endpoint Protection Client';

display_ver = get_kb_item_or_exit('Antivirus/SAVCE/version');
edition = get_kb_item('Antivirus/SAVCE/edition');

if (isnull(edition)) edition = '';
else if (edition == 'sepsb') app += ' Small Business Edition';

if (display_ver =~ "^12\.1\.")
  fixed_ver = '12.1.7166.6700';
else
  audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);

if (ver_compare(ver:display_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Product           : ' + app +
    '\n  Installed version : ' + display_ver +
    '\n  Fixed version     : ' + fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_INST_VER_NOT_VULN, app, display_ver);
