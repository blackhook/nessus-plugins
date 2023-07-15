#TRUSTED 322c9bfa80a5cd9a1caa0c464df79b66efadf48699e8bf5372d35a5ec6f4f251e1860021971cb5c20b07bcd44b8a834177b696e9a90e31a4daac85eb4e5124b56df62cf38a49863e73602aa912be05b9fde6f40a98fecc5d6d2cb811535b4a7f47cfcd401888d7a499d40df9bf290d17447a5119224deb9254085bb1afc700ebf0ea1271a8176b2a19327af11f9d77cf08eedbaf1fae914540d93bcbd7c0137311a6484712d106c3fe6b12fda81bb8195012b9c9c47016a31993da7a7bbf83bef68f2385b80d357078fb477a02988b3810f2f5f252777a0f2724683d2aabdd0093eb8b41ba00d0a976d27ed73f87cbc8362c406af929610b17812ae5bd03354cd747ea1fac14f877f1f87311a2f98f7cbdeada14f532c17ee35eef2a4d7518a2b6bf0084aaad60393a392a003cefc60bd25edc8c84fc104c12ac79b347525b90e4424ab718eaea47b43ca0f17787ac050d5d43a1f99e23a0fb300fbce311536baade8494a3d303a573988a841d572076e97ec6294dcd2bd193cb6f52cc48ebb7d1c32a28ecac0ab31b49dc5d6ad55459113ee9a7168578e1526109559e6cbcdf02786d9f4325b1827c70ad73edd767e9fdccfb724c90584a1c6c81fa6a800583cdb18da6cb2be1e66b676b36c1cabad32c7fd72bd461c363fe022d58d4fee024971c858a8c198d71d3051d0dce391ff1cb77db705cd5730d6428e34730c8ed84
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82569);
  script_version("1.15");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0646");
  script_bugtraq_id(73340);
  script_xref(name:"CISCO-BUG-ID", value:"CSCum94811");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150325-tcpleak");

  script_name(english:"Cisco IOS XE Software TCP Memory Leak DoS (cisco-sa-20150325-tcpleak)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a memory leak issue in the
TCP input module when establishing a three-way handshake. An
unauthenticated, remote attacker can exploit this issue, via specially
crafted TCP packets, to consume memory resources, resulting in a
device reload and a denial of service condition.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150325-tcpleak#@ID
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?86ea2261");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCum94811");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20150325-tcpleak.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCum94811";
fixed_ver = NULL;

if (
  ver =~ "^3.3.[0-2]XO$" ||
  ver =~ "^3.5.[0-3]E$"  ||
  ver =~ "^3.6.[01]E$"
)
  fixed_ver = "3.7.0E";

else if (
  ver =~ "^3.8.[0-2]S$"  ||
  ver =~ "^3.9.[0-2]S$"  ||
  ver =~ "^3.10.[0-4]S$" ||
  ver == "3.10.0S"       ||
  ver == "3.10.0aS"
)
  fixed_ver = "3.10.5S";

else if (
  ver =~ "^3.11.[0-4]S$" ||
  ver =~ "^3.12.[0-2]S$"
)
  fixed_ver = "3.12.3S";


if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);

override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;
  # TCP listening check
  # Example:
  # 03577CD8  ::.22                    *.*                    LISTEN
  # 03577318  *.22                     *.*                    LISTEN
  # 035455F8  ::.80                    *.*                    LISTEN
  # 03544C38  *.80                     *.*                    LISTEN
  buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
  if (check_cisco_result(buf))
  {
    if ( preg(multiline:TRUE, pattern:"^\S+\s+\S+(\.\d+)\s+\S+\s+(LISTEN|ESTAB)", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  # TCP control-plane open-ports
  # tcp                        *:22                         *:0               SSH-Server   LISTEN
  # tcp                        *:22                         *:0               SSH-Server   LISTEN
  # tcp                        *:80                         *:0                HTTP CORE   LISTEN
  # tcp                        *:80                         *:0                HTTP CORE   LISTEN
  buf = cisco_command_kb_item("Host/Cisco/Config/show_control-plane_host_open-ports", "show control-plane host open-ports");
  if (check_cisco_result(buf))
  {
    if ( preg(multiline:TRUE, pattern:"^(\s)?+tcp\s+\S+\s+\S+\s+.*(LISTEN|ESTABLIS)", string:buf))
      flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;
}

if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because nothing is listening on TCP");

if (report_verbosity > 0)
{
  report +=
    '\n  Cisco bug ID      : ' + cbi +
    '\n  Installed release : ' + ver +
    '\n  Fixed release     : ' + fixed_ver +
    '\n';
  security_hole(port:0, extra:report+cisco_caveat(override));
}
else security_hole(port:0, extra:cisco_caveat(override));
