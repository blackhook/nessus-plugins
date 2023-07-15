#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(137004);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2018-0037");
  script_xref(name:"JSA", value:"JSA10871");

  script_name(english:"Juniper Junos RCE (JSA10871)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to the self reported version of Junos OS on the remote device it is affected by a remote code execution
vulnerability in the routing protocol daemon (RPD). An unauthenticated, remote attacker can exploit this, via crafted
BGP NOTIFICATION messages, to crash the RPD process and potentially allow the execution of arbitrary commands.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10871");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10871.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0037");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/06/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

# No fixes available for 15.1F5, 15.1F7, or 15.1R5
if (ver =~ "^15.1F[57]" || ver=~ "^15.1R5")
{ 
  security_report_v4(port:0,extra:'This version is vulnerable. Please, check the vendor\'s advisory for more info.', severity:SECURITY_HOLE);
  exit(0);
}

fixes['15.1F'] = '15.1F6-S10';
fixes['15.1R'] = '15.1R6-S6';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

report = get_report(ver:ver, fix:fix);

security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
