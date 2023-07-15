#TRUSTED 90b60e12bb1dad040956df034a8982a5664299447b13cc1dd85d1c5e3cee9ae73161ccf62e48bfa09f1dfb9b47c562c5811c2445e83c30ebc75629557d129e0594765a7b9bb8b3aed9201331845e79dffc71a5a7accfd6c9610ed3fc3f8a46b363b28aedd2935c7b66124a8b091c9db87ecffb3adbcb6fb8bd1a235ada97b0dbd56d031d3346271c2965d2de2ebe3ae0d9699abaa69a28edec28ca292a3efe85571d5a4b319d813d36a820889b0ccbf53253ceb94f19d4efe859e9d484e3425a2bcc4e2ae72fab55e230e022f5be06fc781a829cb31bcdb75cfdff28055db761a88fa1e5226bcd9c09ffbd29fd22a583779c92a3b924efb014847e2791d0ff0c1ad0ccbfd08e1df9dbee0244410c2aa18903d337cf2b1aaa1731c37544050cbbfc5f9dd0ef75d13d1a9bdf15f280c4e8f95dace8c0b72bef43f18a435ae848b0c50c6dd932beff1e60e3c1f6a9860342e1eeef04c495276a7cc48ba9b45f2b82aa68763abbc5989951ab69d04efa42afe9e9bbd76c6e8821647cb3de84981adc5749739232a12a9e26e288eb3405150ad95bfb204dc5b70a57ebe7e8d05e2b859b91e215427e5cbdf92b0e69cee6664e35c5bdfb6568516b8ee447a70dd61017ef0d27714d63532f325eecd358e5c99bfcb87b68a295444fb27148fd1d497171da73d6392c3987b366f985f59b547d3c55a1dd6eebcf72d24ee83774bd06ab60
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90311);
  script_version("1.9");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2016-1350");
  script_xref(name:"CISCO-BUG-ID", value:"CSCuj23293");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160323-sip");

  script_name(english:"Cisco IOS XE SIP Memory Leak DoS (CSCuj23293)");
  script_summary(english:"Checks the IOS-XE version.");

  script_set_attribute(attribute:"synopsis", value:
"TThe remote device is affected by denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Session Initiation Protocol (SIP) gateway
implementation due to improper handling of malformed SIP messages. An
unauthenticated, remote attacker can exploit this, via crafted SIP
messages, to cause memory leakage, resulting in an eventual reload of
the affected device.");
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

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version  = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
flag     = 0;
override = 0;

affected = make_list(
  "3.8.0S",
  "3.8.1S",
  "3.8.2S",
  "3.9.0S",
  "3.9.0aS",
  "3.9.1S",
  "3.9.1aS",
  "3.9.2S",
  "3.10.0S",
  "3.10.1S",
  "3.10.1xbS",
  "3.10.2S",
  "3.11.0S"
);

flag = 0;
foreach badver (affected)
{
  if (badver == version)
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
      order[1], version
    );
    
    if (report_verbosity > 0)
      report = report_items_str(report_items:report, ordered_fields:order) + cisco_caveat(override);
    else # Cisco Caveat is always reported
      report = cisco_caveat(override);
    security_hole(port:0, extra:report);
    exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
