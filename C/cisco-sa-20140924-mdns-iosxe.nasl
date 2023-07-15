#TRUSTED 0e87f71a5c3c3d6c4b1895752aeb16c722c51508a54cd9a3281f2ae8c956d1b6aa22cf7524e138e1c849cf8c1764b6e23f147330ee877083ccee9402f3395f6f22691b4b03d863198ce4a6f51ebb02ef81c9a5fd13cfc9fcc2896fcf8416eadf37e31488b41e7883b7f3c3917486888aec0d31e2200cb987da8940e042ecef626fdf8205c9c8987ba4ec96a45cc8ad527c6f9810f85a939068150f37d4331d47b6c7201fe7ea08a7619f20c9afcc6f7b62c1aa9773bd3c82d850b6ce2f1eda031f7f53e01ac1d195ac657433c510f55a61788761dc9358b123bab6c3bfe11db58553d35ab1c208c7646c3680ad8a77c2a3afe02bb01a0f5d947922f170e717d88aa7e917aab108e8c632284959863797581f358e216c7a804d45b3aa4a6a0008124d1639409568815b579a7ccad8ed8127e3547b5b450d9171a07e07c5416faf764264cf41a8ca79c1f230a136c6252ba1e1685ea88dd3ee84db5fb8cf4bc862744ac2bba9bb6f8fd99931032e5f6a955576538f99edfbab28d88c7e15af3dfd8ee09c6a03dfd1eef3a43782c789fa0091d76349e49ed2d7497b088d523560223de53ac99a6f1ea34a05cfeaa2bf8dd14ced8911fddaf347e024af398a674e79a8ffd516ad63d7574a26a111e00c448dc96360dc782578ae735bf24bb986e4efbc274e2d13c287a66c7944bffd1d2565216fd8e73ec450fb2948a92707259c6c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78030);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2014-3357", "CVE-2014-3358");
  script_bugtraq_id(70132, 70139);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj58950");
  script_xref(name:"CISCO-BUG-ID", value:"CSCul90866");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20140924-mdns");

  script_name(english:"Cisco IOS XE Software Multiple mDNS Gateway DoS Vulnerabilities (cisco-sa-20140924-mdns)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XE
running on the remote host is affected by two unspecified denial of
service vulnerabilities in the multicast DNS (mDNS) implementation. A
remote attacker can exploit this issue by sending a specially crafted
mDNS packet to cause the device to reload.

Note that mDNS is enabled by default if the fix for bug CSCum51028 has
not been applied.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140924-mdns
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e2f51db1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAMBAlert.x?alertId=35023");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35607");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=35608");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCuj58950");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/bugsearch/bug/CSCul90866");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20140924-mdns.");
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
cbi = "CSCuj58950 and CSCul90866";
fixed_ver = NULL;


if (
  ver =~ "^2\.[16]\.[0-2]$" ||
  ver =~ "^2\.2\.[1-3]$" ||
  ver =~ "^2\.3\.([02]|[01]t)$" ||
  ver =~ "^2\.4\.[01]$" ||
  ver == "2.5.0" ||
  ver =~ "^3\.1\.[0-3]S$" ||
  ver =~ "^3\.[2356]\.[0-2]S$" ||
  ver =~ "^3\.4\.[0-6]S$" ||
  ver =~ "^3\.7\.[0-4]S$"
)
  fixed_ver = "3.7.6S";

else if (
  ver =~ "^3\.2\.[0-3]SE$" ||
  ver =~ "^3\.3\.[01]SE$"
)
  fixed_ver = "3.3.2SE";

else if (ver =~ "^3\.3\.[0-2]SG$")
{
  cbi = "CSCuj58950";
  fixed_ver = "3.4.4SG";
}
else if (ver =~ "^3\.4\.[0-3]SG$")
  fixed_ver = "3.4.4SG";

else if (ver == "3.3.0XO")
  fixed_ver = "3.3.1XO";

else if (ver == "3.5.0E")
  fixed_ver = "3.5.2E";

else if (
  ver =~ "^3\.8\.[0-2]S$" ||
  ver =~ "^3\.9\.[01]S$" ||
  ver =~ "^3\.10\.(0|0a)S$"
)
  fixed_ver = "3.10.4S";

else if (ver =~ "^3\.11\.[12]S$")
  fixed_ver = "3.12.0S";

if (isnull(fixed_ver)) audit(AUDIT_INST_VER_NOT_VULN, app, ver);


# mDNS check
override = FALSE;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
  if (check_cisco_result(buf))
  {
    if (preg(multiline:TRUE, pattern:"^17\S+\s+\S+\s+5353\s+", string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because mDNS is not enabled.");
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
