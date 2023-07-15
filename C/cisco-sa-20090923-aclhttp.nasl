#TRUSTED 62e57d81441cd81455a8f27fbdc1b7d49c8ea73723ea56aa575a5ebc4526705a78c96aab31c8d71536049c12ae78c6ae2d41e2b89b8cfcde3dc363457c783377e9080625fa9912a3aa466210da59baec7b33e37b283695183a75597e1aea5f98f13c887b011964c2a21884accd41358a86efa06e3ab2c89063ca02efeaeb0ece396d41ff2009652228239359b37d861f8734d0ee57405fc26d757f5e96f8bdee944ff65c39eae8c1010774ebb19c7ef86a8c87769afd06608dfd1c125bc8455324b86f15a5b91ab2a798f53857d9adf951a692345f134f312b32c699caaf3caa79839c905336df8e1ea972dc9c6f109b409f3aed5f1ea311dee502f2a872c831757669ce32b410971f5c3357c96ac0caf99b5778c2a217a7c4023424f434ef61ad416def49c7240e879033b61b486f9c77bae6418c462bab04384391eba39706d31d44964cd9b680b2d2bde9c576710488868fe0e981f6700a455caa0fe999e9905372380ebcd6da266151b031bb4acc4432ff3dadbe8811789c7c07a2c0ade8282e643c5e5f7800d701366d9fd4d2fe91f9a492cc17584ff695970fda91e3b0c93977487835e5b2a354702ce0e25fdea527b6b502f97f3fdc4e39790b18cd308090f672e5f208741c6b9dec2534a9fd41a8c02831e49f97a877b5b6c8079ab19a30fe46081eb0d613f7309bf9a7077d5647507682e1c78ff00322c899799a72
#
# (C) Tenable Network Security, Inc.
#
# Security advisory is (C) CISCO, Inc.
# See https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8119.shtml

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
 script_id(49039);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");
 script_cve_id("CVE-2009-2862");
 script_bugtraq_id(36495);
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu50252");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsu70214");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsv48603");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsw47076");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsx07114");
 script_xref(name:"CISCO-BUG-ID", value:"CSCsy54122");
 script_xref(name:"CISCO-SA", value:"cisco-sa-20090923-acl");
 script_name(english:"Cisco IOS Software Object-group Access Control List Bypass Vulnerability - Cisco Systems");
 script_summary(english:"Checks the IOS version.");
 script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
 script_set_attribute(attribute:"description", value:
'A vulnerability exists in Cisco IOS software where an unauthenticated
attacker could bypass access control policies when the Object Groups
for Access Control Lists (ACLs) feature is used. Cisco has released
free software updates that address this vulnerability. There are no
workarounds for this vulnerability other than disabling the Object
Groups for ACLs feature.
');
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e298deb3");
 # https://www.cisco.com/en/US/products/products_security_advisory09186a0080af8119.shtml
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?b473abac");
 script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20090923-acl.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

 script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/23");
 script_set_attribute(attribute:"patch_publication_date", value:"2009/09/23");
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
override = 0;
version = get_kb_item_or_exit("Host/Cisco/IOS/Version");

if (version == '12.4(22)YE') flag++;
else if (version == '12.4(22)YD') flag++;
else if (version == '12.4(22)YB1') flag++;
else if (version == '12.4(22)YB') flag++;
else if (version == '12.4(20)YA3') flag++;
else if (version == '12.4(20)YA2') flag++;
else if (version == '12.4(20)YA1') flag++;
else if (version == '12.4(20)YA') flag++;
else if (version == '12.4(15)XZ2') flag++;
else if (version == '12.4(15)XZ1') flag++;
else if (version == '12.4(15)XZ') flag++;
else if (version == '12.4(24)T') flag++;
else if (version == '12.4(22)T1') flag++;
else if (version == '12.4(22)T') flag++;
else if (version == '12.4(20)T3') flag++;
else if (version == '12.4(20)T2') flag++;
else if (version == '12.4(20)T1') flag++;
else if (version == '12.4(20)T') flag++;
else if (version == '12.4(22)MF') flag++;
else if (version == '12.4(22)MDA') flag++;
else if (version == '12.4(22)MD') flag++;
else if (version == '12.4(22)GC1') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show object-group", "show object-group");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"Network object group ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}



if (flag)
{
  security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
