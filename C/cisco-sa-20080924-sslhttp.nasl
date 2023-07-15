#TRUSTED 8f6a25513ae0cd41d68e4d076202eb6372fd4b2ca9db4b43a148e4b5810b37408f8f320fab93a4dec2c5b25233150da9eee09416b4c18c8a3022eac16fbe89fab1a30c46acbbf33d7b1bc49ce2b60a9d98e54d7da205fbf18abbb59ba47f0e3078af4a175ba52ef44cd889bdca71b9de123377d8bee102eb0e70bd010c2c90dd7d584be89a64718a59140995f1fe8904056e51fb090e0688c0738e8a03a551f77c01439de96501b0be019ec6e1996d79952ab8436333e69c9a578b6aced300a71ac0af1a409a951062a101b0817d8bd8f006510ab6d5eddc3d25ebec10ad8d86b13ba64296a9c136e4c9c59ad2313bdb3bff7b2d113fe83f5b6bed632caf40c58fe42f1489af4fb92c1d612f3d1af1fb661e1c60c43e0be8f4c8ada310a770f4d440517be34cad68c8a1f8f74f79dcb405ea9ba1f5f48cf2436288b0f242405c6774ee688b5dde92cba28b2741492f39681a87c098414431ed8769a48e9168f3568ffbe1020cb9c97d6c101ff6938fa136e5c932c1471a47e6eceb926181d6acb6a9335ca75b9e9acd163fd1abecc386dad4367072c8bcf554aea21640f089991299f97a82aa2b8974d446485839c1bb6c6d3e94ea3b55c493e21907bec7fc2893a2a92cc96f59402f870c673607fc9f0a42e49398d4a722e8f96194a475cd1c5ef6fb28d7b8b3b03026aa890ceb079315e417be87994a461d11f8ce88918a49
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080a0146c.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49026);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2008-3798");
 script_bugtraq_id(31365);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsj85065");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20080924-ssl");
 script_name(english:"Vulnerability in Cisco IOS While Processing SSL Packet - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A Cisco IOS device may crash while processing an SSL packet. This can
happen during the termination of an SSL-based session. The offending
packet is not malformed and is normally received as part of the packet
exchange.
Cisco has released free software updates that address this
vulnerability. Aside from disabling affected services, there are no
available workarounds to mitigate an exploit of this vulnerability.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d0cb496f");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080a0146c.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?0c359932");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20080924-ssl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/09/24");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/09/01");

 script_end_attributes();
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is (C) 2010-2018 Tenable Network Security, Inc.");
 script_family(english:"CISCO");
 script_dependencie("cisco_ios_version.nasl");
 script_require_keys("Host/Cisco/IOS/Version");
 exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;#

version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(16)MR2') flag++;
else if (version == '12.4(16)MR1') flag++;
else if (version == '12.4(16)MR') flag++;
else if (version == '12.4(17)') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ip http secure-server", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"webvpn enable", multiline:TRUE, string:buf)) { flag = 1; }
      if (preg(pattern:"url https[^\r\n]+:443", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
