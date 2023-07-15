#TRUSTED 858f8302052692ee28ae24b3c344c0e206e5e2dfc36b8c64dbdfc024a1d84dcc70e4cf6b55c2af7caee8044b83452dc51645856447c28bd165188d00a7b3981e03b2fbab432d307801da3cd74405bf42ac2798f3cfcdbc0d6e7cf43b16f0685b51a26f21228defce482de04e5f2e62bb37b5383ffe74f9d94d08d1a5d99dfdff53ea979cac01e05b8264da0d1d63b2ec7667f9b793a544de9bac6deff19d641692245aee329bea85a10193eb13e843bb1cbb0e61905a284ac63a83634e3482bf6ada306bc0fc812903ae72b3bfc50f2d76fadbdd54c7a592e384385b69a9fff6800c37013570074838738dec639ef7e4b2563fea796166b6d93079ea8032557e4db124490ee1445b1d17082b1566c8bfc9575ee621dab5fd9a22c53f6efc33c2cf78ae66d35eec3124a5b688a06fe85a160a6522346e75af75b4d9732a6d2fe064c9269d64950a7acb86001e961f8bd7a55035a6f4e8725621272e99b42c6b75bd1e3385d483bcc55059c917d4eadc2ce93a8449ea431f1f401fddef863ef70a8b24b3d23e724020354567b60d83c690cf145c965f8ce10d186be3d97ba1b31ac4a08a42a665c1380a3a5f06d8c008af74d5cacfd2ecab1d5b3f4f61b26d5f317c91d790e492d058490198bec21e52e91bea8906e2c67f082b836e4b8e97771b8fd83258944a0b73d7948df1ce5aafece5f35485ccd4096b35b20287545b2cc9
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70312);
  script_version("1.17");
  script_cvs_date("Date: 2019/11/27");

  script_cve_id("CVE-2013-5478");
  script_bugtraq_id(62646);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf17023");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-rsvp");

  script_name(english:"Cisco IOS XE Software Resource Reservation Protocol Interface Queue Wedge Vulnerability (cisco-sa-20130925-rsvp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Resource Reservation Protocol (RSVP) feature
of Cisco IOS XE Software allows an unauthenticated, remote attacker to
trigger an interface queue wedge on the affected device. The
vulnerability is due to improper parsing of UDP RSVP packets. An
attacker can exploit this vulnerability by sending UDP port 1698 RSVP
packets to the vulnerable device. An exploit can cause Cisco IOS XE
software to incorrectly process incoming packets, resulting in an
interface queue wedge, which can lead to loss of connectivity, loss
of routing protocol adjacency, and other denial of service (DoS)
conditions. Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.

Note that this plugin checks for an affected IOS XE version and does
not attempt to perform any additional validity checks.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-rsvp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fe2616f7");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-rsvp.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-5478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2013-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if ((version =~ '^3\\.[2-4](\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.4.6S') == -1)) fix = '3.4.6S';
else if ((version =~ '^3\\.[5-7](\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.7.4S') == -1)) fix = '3.7.4S';
else if ((version =~ '^3\\.[9](\\.[0-9]+)?S$') &&(cisco_gen_ver_compare(a:version,b:'3.9.2S') == -1)) fix = '3.9.2S';

if (fix && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_rsvp", "show ip rsvp");
  if (check_cisco_result(buf))
  {
    if ("RSVP: enabled" >< buf) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }

  if(flag == 0) audit(AUDIT_OS_CONF_NOT_VULN, "Cisco IOS XE", version);
}

if (fix || flag)
{
  security_report_cisco(port:0, severity:SECURITY_HOLE, version:version, override:override, bug_id:'CSCuf17023', fix:fix);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
