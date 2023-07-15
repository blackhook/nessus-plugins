#TRUSTED 119de78e9a7d80bc714dca7df21c09ade6648e6e4eb01ca1daf1e629079e1a605168900953cc36a16daf22756799d1912e31329195fb5229da07d18a41ba376722d50061d2089dae5fe7a1a7cade2a0ac68f6e4c3cbb46f9e12833bced7836c98bd19573b251caa5733b2601ccd610e412d0e7445929a9002b2fae8dfd5c1dc2e2ca08f8fb4e4f0cd705b156170f8ea77a67471860a2fafa2e64839fd9d802dc9b38e8d74c29fe7a872c0bac3ae25b5666e5849043ad1b26024b7ce6ce252ba2ab6cff93557d48bae286969770235f9231b2754e3ccebacc0a0c2ecd1d714a0412a5e7c2346848c98fff97500568804c3b191235822e97d9ef269327b2682aeaaa74ce9295128feabe6d6d8db7a607ef837eb0ec08233e39a53ea36565ae6360d836f6c19cb92cc9e8819459a8ec73d8873329929e018fbe4f2dca0397476b2a525d269f0c63b9cbd62d2cb9e0c3f4b0e1c31b21010cb8ee2d09a1f27d2889401d779440638815315da0a0cab6298209779210b435a9328f90c3f030d13205d02fc5ee0d36178423d59ddd32e7dbe152815efcdc2ac480f4ef06bbd2b4bb9fc4bcdb3f414aac57520e3f28c2b13aa55985a81e2869769f37f51b35ef11b6e6009be4a6f1ae448affdbf11ef261f881a8ef84632ec4cd62cb14f572021327b82290eeb3b994e492fc0709ecb33c5c33d114650234c5435351e6ade3d2a754bfba
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120328-nat.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(58569);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2012-0383");
  script_bugtraq_id(52758);
  script_xref(name:"CISCO-BUG-ID", value:"CSCti35326");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120328-nat");

  script_name(english:"Cisco IOS Software Network Address Translation Vulnerability (cisco-sa-20120328-nat)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Cisco IOS Software Network Address Translation (NAT) feature
contains a denial of service (DoS) vulnerability in the translation of
Session Initiation Protocol (SIP) packets. The vulnerability is caused
when packets in transit on the vulnerable device require translation
on the SIP payload. Cisco has released free software updates that
address this vulnerability. A workaround that mitigates the
vulnerability is available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120328-nat
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?cc989057"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120328-nat."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/02");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}



include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");
if ( version == '12.4(24)GC4' ) flag++;
if ( version == '12.4(24)MD5' ) flag++;
if ( version == '12.4(24)MD6' ) flag++;
if ( version == '12.4(24)MDA10' ) flag++;
if ( version == '12.4(24)MDA6' ) flag++;
if ( version == '12.4(24)MDA7' ) flag++;
if ( version == '12.4(24)MDA8' ) flag++;
if ( version == '12.4(24)MDA9' ) flag++;
if ( version == '12.4(24)MDB' ) flag++;
if ( version == '12.4(24)MDB1' ) flag++;
if ( version == '12.4(24)MDB2' ) flag++;
if ( version == '12.4(24)MDB3' ) flag++;
if ( version == '12.4(24)T5' ) flag++;
if ( version == '12.4(24)T6' ) flag++;
if ( version == '15.0(1)M4' ) flag++;
if ( version == '15.0(1)M5' ) flag++;
if ( version == '15.1(1)T2' ) flag++;
if ( version == '15.1(1)T3' ) flag++;
if ( version == '15.1(1)XB3' ) flag++;
if ( version == '15.1(2)T4' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"\n\s*ip nat (inside|outside|enable)\n", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
