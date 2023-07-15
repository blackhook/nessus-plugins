#TRUSTED 0299338de26f3df2ecb0a2ec61c4d1678336c21b4b4e94ac71d5688e2e37032b4ca0ea63e13fd346e41eb7eb1fa076ca6cdd906491329580d912d79f6c0e812e2fe3d2759b174b559c3fabf9dcccbaeeb1ea3ecccba0f27428456dff27ff90f2a0cabd241757eef8d13a44efabe97174c04974c0a83d71f94220eecad7962809c4a7dde4e823f7f37eb7ac9497f294476729baf51164f014e94bc519e50995ee35b22127a565f23ed4916370bee9757745b76fa0bc520b66ab0ac72c226dd9557b47e46c501d1891fb0deb0caf003085b92bde0448661f9d967a37e16e33b61f0ab90fb4ed21bb2d7a82a3586f31467e51a9c0c1f49a058230fca2f1c4db079cf30a3a39ad4f17512137ce6f2b8a42e0cb01aeb0183a2dff0b32e324265d069a1f5828cf3308c4e305f8e3db807b4b985981e1bfcfad3a4dda82130737b39a80f6d2d9e148899f7666260edd7727964a07c01d979d84e252588fdc334106dcf99c0a0f99c807e52e82364c00fba9935b8d7bd12706d517963a7ce49f18f064115c0fe5851138bd265fc20efd977a5ee42c23828dea1615636fee0193537d7e894fe4278480455d60ffe832cdba9595d2d7f64d0c09464d5a684d8c77991100904c9a055d07dfe41932f445ef0357b9efb505dc52a7d5934181beb0e129fec169bcb5416d673918a7227715911561da17b7a480905a7cab3cb0090ef8b867f690
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90310);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1350");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23293");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-sip");

  script_name(english:"Cisco IOS SIP Memory Leak DoS (CSCuj23293)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Session Initiation Protocol (SIP) gateway implementation due to
improper handling of malformed SIP messages. An unauthenticated,
remote attacker can exploit this, via crafted SIP messages, to cause
memory leakage, resulting in an eventual reload of the affected
device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160323-sip
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ddc3f527");
  script_set_attribute(attribute:"see_also", value:"https://quickview.cloudapps.cisco.com/quickview/bug/CSCuj23293");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in the Cisco security advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1350");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

affected = make_list(
  "15.3(3)M",
  "15.3(3)M1",
  "15.3(3)M2",
  "15.3(1)S1",
  "15.3(1)S2",
  "15.3(2)S0a",
  "15.3(2)S2",
  "15.3(1)T",
  "15.3(1)T1",
  "15.3(1)T2",
  "15.3(1)T3",
  "15.3(1)T4",
  "15.3(2)T",
  "15.3(2)T1",
  "15.3(2)T2",
  "15.3(2)T3",
  "15.3(2)T4",
  "15.4(1)CG",
  "15.4(2)CG",
  "15.4(1)T",
  "15.4(1)T1",
  "15.4(2)T"
);

flag = 0;
foreach badver (affected)
{
  if (badver == ver)
  {
    flag = 1;
    break;
  }
}

# Configuration check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  pat = " CCSIP_(UDP|TCP)_SOCKET(\r?\n|$)";
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_processes_include_sip","show processes | include SIP ");
  if (check_cisco_result(buf))
  {
    if (
      preg(multiline:TRUE, pattern:pat, string:buf)
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag)
{
    order  = make_list('Cisco bug ID', 'Installed release');
    report = make_array(
      order[0], "CSCuj23293",
      order[1], ver
    );
    
    if (report_verbosity > 0)
      report = report_items_str(report_items:report, ordered_fields:order) + cisco_caveat(override);
    else # Cisco Caveat is always reported
      report = cisco_caveat(override);
    security_hole(port:0, extra:report);
    exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
