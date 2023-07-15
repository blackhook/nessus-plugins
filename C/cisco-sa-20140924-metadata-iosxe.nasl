#TRUSTED 1986eedb8734cd194e20b7222806235988cb442bee7492f533d217ee1754646ffa0585ad1cad0060df4f152f20a55e40e6b47443a3a6f781cc397c2429bbea7a213269c3423501250d04484ba1a7631fb8ea64f9a5d5e486a43f059589e37ed288b2444a29fed6437bdf5ed8df8252de33a42fbe1a725059199c91cb7c7ed96da13d511ef297231cf7c054436368d7933c4236e5b4befbd8827ec94c47189b5bb9bb5461bc2fed661725040923b316a8ccfbabc4d02472541935ab4992d277bc9b051048f43e3f7e18aac2e012b2ea55dfa25bf1006996d645ee53d20af4bdbda3abef5ad86603223e064b954291ebce0e3a229786c69b2ff6d3a51f983c1761dbeee877f4a979a76db6d01273b46886bb59c42c6cccad936dd2ab0ce144869b6af66e9b1e1cc3b594c31809210435f6846c47181ab7ecd6e23673999844826c59dd10bc571aefae4c743c511a3e2a559c078318a3e62a9b71d52f96db7db4694d678f6c2d2b72cbcfe8557884f6a849eb7296c8a03759b35ff93651a0da4361395fe8fbf1e8eafcdf08eb771cdfdd8c2e221935ebd16a6eab9ecbdc5891e731e608604be078a95e47c4cee435d67db1aac7928681993db2f832bf6faf2d2b1d67106be342e6c7f23c7ca133468067e2be4a583a275b990d45df3fd970e6a1f1ba76de50dc3ee21587dbe6663d9abdb9d0e0a1a7d97f345029add1d5a78507b9
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78032);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3355", "CVE-2014-3356");
  script_bugtraq_id(70130, 70135);
  script_xref(name:"CISCO-BUG-ID", value:"CSCue22753");
  script_xref(name:"CISCO-BUG-ID", value:"CSCug75942");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-metadata");

  script_name(english:"Cisco IOS XE Software Multiple IPv6 Metadata Flow Vulnerabilities (cisco-sa-20140924-metadata)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by two vulnerabilities in the
IPv6 metadata flow feature due to improper handling of RSVP packets. A
remote attacker can exploit this issue by sending specially crafted
RSVP flows to cause the device to reload.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-metadata
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?102835df");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35622");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35623");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCue22753");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCug75942");

  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-metadata.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

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
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

app = "Cisco IOS XE";
cbi = "CSCue22753 and CSCug75942";
fixed_ver = NULL;


if (
  ver =~ "^3\.6\.[0-2]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.(8|10)\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$"
)
  fixed_ver = "3.10.4S";

else if (ver == "3.3.0XO")
{
  cbi = "CSCug75942";
  fixed_ver = "3.3.1XO";
}

else if (ver == "3.7.5S")
{
  cbi = "CSCue22753";
  fixed_ver = "3.7.6S";
}
else if (
  ver == "3.9.2S" ||
  ver =~ "^3\.10.(0a|3)S$"
)
{
  cbi = "CSCue22753";
  fixed_ver = "3.10.4S";
}

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  # metadata flow check
  buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^\s*metadata flow$", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override)
  {
    # IPv6 metadata flow check
    buf = cisco_command_kb_item("Host/Cisco/Config/show_metadata_flow_table_ipv6", "show metadata flow table ipv6");
    if (check_cisco_result(buf))
    {
      if (preg(multiline:TRUE, pattern:"^Flow\s+Proto\s+DPort\s+SPort", string:buf)) flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) override = TRUE;
  }

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the metadata flow feature is not enabled.");
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
