#TRUSTED 525341c716d65021643a7d4768164334e28f30bddcc8fe2edd5cd69e95871edac1f5e43629bc7dbbfec0ccb97974bf1db90fde93547b09b70e7b32257fbe23f201b73b3ac736732f35fc577c41362c2873718a43020e416f9a29626375e0c369a257e5e9fd319fb980291e644e9a7a74e1bbcc015acfd51b647a0bf1ba0787210f623767b2eb0d33653eb42e9fd164fd72dda6d012c37661fa1b90f09050cabeb916720decd4548faff0440d238043a5fa5781ff681930abcaf1f6a08a17a5b8db23280e31855502d1a9ee0192482eb9969b0adb09509cef063d0c979f400b6dce34b051914f80ea519ccc3f48d084d355ad18739cbce1ed51c87a8e6be25d21cc071c6b312a51d1f86619c7881072a8768831049cb5e702cde227381771feafc5cb0168df043bea62ff86e9e1f4053532bcdebcc1672e7f9726cb3496b589b992db3e03435a55a96c7dcebfb526ea9cb13c35c8e175053c06e6f29c08418276cd4042846aee81576de74cac5b4f908d79cc55783c95a5bc56be9f7e421ac3bab4daa9c5a61220b9987213b625641798900081dc86d99a6d76aef8e2be40595184f439b0789322a23449f9077d970a220a8ef297b20a2b8f49daaed0d53368a859c6a89a4fee8d9edbcb8ba28bc7676ea158bda5db0b9cfaad872f80ba8c3a2d92e1e411b0e66867b3ecd3a3938fc81ad2a066e99da7431a2979a10155451b81
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ike.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70318);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5473");
  script_bugtraq_id(62643);
  script_xref(name:"CISCO-BUG-ID", value:"CSCtx66011");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ike");

  script_name(english:"Cisco IOS Software Internet Key Exchange Memory Leak Vulnerability (cisco-sa-20130925-ike)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability exists in the Internet Key Exchange (IKE) protocol of
Cisco IOS Software that could allow an unauthenticated, remote attacker
to cause a memory leak that could lead to a device reload. The
vulnerability is due to incorrect handling of malformed IKE packets by
the affected software. An attacker could exploit this vulnerability by
sending crafted IKE packets to a device configured with features that
leverage IKE version 1 (IKEv1). Although IKEv1 is automatically
enabled  on a Cisco IOS Software when IKEv1 or IKE version 2 (IKEv2)
is configured the vulnerability can be triggered only by sending a
malformed IKEv1 packet. In specific conditions, normal IKEv1 packets
can also cause an affected release of Cisco IOS Software to leak
memory. Only IKEv1 is affected by this vulnerability. An exploit
could cause Cisco IOS Software not to release allocated memory,
causing a memory leak. A sustained attack may result in a device
reload. Cisco has released free software updates that address this
vulnerability. There are no workarounds to mitigate this
vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ike
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bfaf2180"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130925-ike."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
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
if ( version == '15.1(3)MR' ) flag++;
if ( version == '15.1(3)S2' ) flag++;
if ( version == '15.1(3)S3' ) flag++;
if ( version == '15.1(3)S4' ) flag++;
if ( version == '15.1(3)S5' ) flag++;
if ( version == '15.1(3)S5a' ) flag++;
if ( version == '15.1(4)M3' ) flag++;
if ( version == '15.1(4)M3a' ) flag++;
if ( version == '15.1(4)M4' ) flag++;
if ( version == '15.1(4)XB7' ) flag++;
if ( version == '15.1(4)XB8a' ) flag++;
if ( version == '15.2(2)S' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)T' ) flag++;
if ( version == '15.2(3)T1' ) flag++;
if ( version == '15.2(3)T2' ) flag++;
if ( version == '15.2(3)XA' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"crypto gdoi enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"crypto map", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"tunnel protection ipsec", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
