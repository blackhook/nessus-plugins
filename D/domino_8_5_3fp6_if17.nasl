#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(105411);
  script_version("1.5");
  script_cvs_date("Date: 2019/11/08");

  script_cve_id("CVE-2017-1274");
  script_bugtraq_id(98019);
  script_xref(name:"CERT", value:"574401");

  script_name(english:"IBM Domino 8.5.x < 8.5.3 FP6 IF17 / 9.0.x < 9.0.1 FP8 IF2 IMAP EXAMINE Command Handling RCE (EMPHASISMINE) (credentialed check)");
  script_summary(english:"Checks the version of IBM Domino.");

  script_set_attribute(attribute:"synopsis", value:
"A business collaboration application running on the remote host is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Domino (formerly IBM Lotus Domino) installed on the
remote host is 8.5.x prior to 8.5.3 Fix Pack 6 (FP6) Interim Fix 17
(IF17) or 9.0.x prior to 9.0.1 Fix Pack 8 (FP8) Interim Fix 2 (IF2).
It is, therefore, potentially affected by a remote code execution
vulnerability when handling the IMAP EXAMINE command. An
authenticated, remote attacker can exploit this, using a specially
crafted mailbox name in an IMAP EXAMINE command, to cause a
stack-based buffer overflow, resulting in a denial of service
condition or the execution of arbitrary code.

EMPHASISMINE is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  # http://www-01.ibm.com/support/docview.wss?uid=swg22002280
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7372eadf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Domino version 8.5.3 FP6 IF17 / 9.0.1 FP8 IF2 or later.

Alternatively, customers using 8.5.1, 8.5.2, and 9.0.0 can open a
service request with IBM Support and reference SPR SKAIALJE9N for a
custom hotfix.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1274");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/12/21");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:domino");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_domino");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lotus_domino_installed.nasl");
  script_require_keys("installed_sw/IBM Domino", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

# Paranoid as special fixes are unknown to us
if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "IBM Domino";

installs = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
base = installs['Base Version'];
fp = installs['Feature Pack'];
hf = installs['Hot Fix'];
path = installs['path'];

if (base == UNKNOWN_VER)
  audit(AUDIT_VER_NOT_GRANULAR, app, base);

domino_ver = base + "." + fp + "." + hf;
domino_ver_display = base + " FP" + fp + " HF" + hf;

if (base =~ "^8\.5($|[^0-9])")
{
  fixed_base = "8.5.3";
  fixed_fp = "6";
  fixed_hf = "3150";
}
else if (base =~ "^9\.0($|[^0-9])")
{
  fixed_base = "9.0.1";
  fixed_fp = "8";
  fixed_hf = "172";
}
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, domino_ver_display, path);

fixed_ver = fixed_base + "." + fixed_fp + "." + fixed_hf;
fixed_ver_display = fixed_base + " FP" + fixed_fp + " HF" + fixed_hf;

if (ver_compare(ver:domino_ver, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item('SMB/transport');
  if (isnull(port)) port = 445;

  report =
    '\n  Path              : ' + path +
    '\n  Installed Version : ' + domino_ver_display +
    '\n  Fixed Version     : ' + fixed_ver_display  +
    '\n';
  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, domino_ver_display, path);
