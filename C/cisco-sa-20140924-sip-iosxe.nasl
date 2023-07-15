#TRUSTED 369da47b2469181d9c07a8b764e9fa0f044f1da67607a7257ce39ab2d44fe0f57566bde77acd8bf0f8ec24fd38c875e5056941251cd650c64173638f1bef030105994792e0538ce29ef8186f33db306d2b27dbd24a2e863758e67d73dc09e9c18b22a81310665f9086ce1d9bc61bb0ace7979b5c8cc48d6ca606bba6f16d0c164aa5aed3b302a03b4543b82aab928f1cd399048edcf1b93496d76500d2097fec628aaffe614ed6e59ec1a99ca97ca182bb81b8efc671c64c37bf4b833ff800f4d75240427e57d0713abcf9d6979466bb171846d0e9bad0791462f022ff26dbe0f2b2a8407857832a65b8d7b881ddb68fe0a2d422cf22f55367fe1e78f8b69b25bce878deef65265f606ce502d0ef49c27da159c81b199fbbcd99c32ad3f20a3e1ac7c09ef563702e19f3ab57ee63c330a4862bc639db9a168c01f672feca063111c6bda5a8aa16396885290b333d381d51d1661fa2b9e61122447961c700b1d59f67c0a00c4702fff2c775d3c3fc77bdbdb9c589ebbae875c89f39982f173d01e4b7331a6d7db76dedd9ac5da9adfa50df48b45605178c5eb7152ffc388014094e4ec7e87f9b4883055e3bbf04931198a92c28c0d4b4cda1666026dc78a4e0ff8d5eceb5d75c83747fb9c76e3d5b32d155f21bdd879106cd43bdee1b1a0771f7a01632ac20c5ed0633031381c55035c126bb88ebe4709f75e0e8489ab85aed08
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78036);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3360");
  script_bugtraq_id(70141);
  script_xref(name:"CISCO-BUG-ID", value:"CSCul46586");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-sip");

  script_name(english:"Cisco IOS XE Software SIP DoS (cisco-sa-20140924-sip)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by a vulnerability in the
Session Initiation Protocol (SIP) implementation due to improper
handling of SIP messages. A remote attacker can exploit this issue by
sending specially crafted SIP messages to cause the device to reload.

Note that this issue only affects hosts configured to process SIP
messages. SIP is not enabled by default on newer IOS XE versions.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00b78a3e");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35611");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35259");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul46586");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-sip.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCul46586";
fixed_ver = NULL;

if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^2\.6\." ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-5]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (
  ver =~ "^3\.3\.[0-2]SG$" ||
  ver =~ "^3\.4\.[0-3]SG$"
)
  fixed_ver = "3.4.4SG";

else if (ver =~ "^3\.5\.[01]E$")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[0-2]S$" ||
  ver =~ "^3\.10.(0a|[0-3])S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# SIP check
# nb SIP can listen on TCP or UDP
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # SIP UDP listening check
  # Example:
  # 17     0.0.0.0             0 --any--          5060   0   0    11   0
  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*(?:\S+\s+){4}5060\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # SIP TCP listening check
    # Example:
    # 7F1277405E20  0.0.0.0.5061               *.*                         LISTEN
    # 7F127BBE20D8  0.0.0.0.5060               *.*                         LISTEN
    buf = cisco_command_kb_item("Host/Cisco/Config/show_tcp_brief_all", "show tcp brief all");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^\S+\s+\S+(506[01])\s+", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because SIP is not listening on TCP or UDP.");
}

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
