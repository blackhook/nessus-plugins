#TRUSTED 9bbc702d9bc38b1751543c8e90faa67da799c817e0b061d62cf03ed3225d9fce0d119463ba5006682143ffb906fc2956a531ff4d294d56bc9e4334ad4ab60608074ca6b5d1b607db3e540d02b1af5260b3c6ce9c48f1ab0e52c8b94a41fc0aaeb1b590814b68a962f1adc13408f55f36fae76b8408724df89b3b93c44aa99d8887a082fbbef418612875defe54336a3836d525aff6276ea3b441f57f8fe07bdd94432f1b985058349553c2c1bae58a1524f6ca529cddb8ed8352fbf954386a59f1230f75edca6ecb94f6539b4a1dc9736d134c8307e0af213aff2c9f4ff9f9b1256d1c68f6bd52ef2512891dad60ce7e1bdd1de5535bcb64c98028c2308e94c56e1a657b2c3fcda540148e981ca72adaeca8a4da2c3cb4aa241b442048e05ec25f9c858b7e70cad58582df57fbc4be350ff3754ca88844581160769f069f2a672f52caf863864f1855f4ca905318998c0dacef796a62fe52120e8df1b655775370eea30747a6009ddb71f88a740014f8f2190a6a171d34d502cd99769f9c958bbab3630ab9d790143309825807541ad13e4646ee1c65fef553ff31f3da71230d246ba0960ee00e93abc823561076d70c09c0e9e65726ba93a4ce35548fd0172a0d317d836555f77894411d441d59a1cd694d25ed921a7ccbd7649bc16c244d5331fb6d0cc6bb1e42f8c04c815581a7e8d1d68283c333bd5c60d7e6ab56b83b24
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-ntp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70321);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-5472");
  script_bugtraq_id(62640);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuc81226");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-ntp");

  script_name(english:"Cisco IOS XE Software Multicast Network Time Protocol Denial of Service Vulnerability (cisco-sa-20130925-ntp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the implementation of the Network Time Protocol
(NTP) feature in Cisco IOS XE Software allows an unauthenticated,
remote attacker to cause an affected device to reload, resulting in a
denial of service (DoS) condition. The vulnerability is due to
improper handling of multicast NTP packets that are sent to an
affected device encapsulated in a Multicast Source Discovery Protocol
(MSDP) Source-Active (SA) message from a configured MSDP peer. An
attacker can exploit this vulnerability by sending multicast NTP
packets to an affected device. Repeated exploitation can result in a
sustained DoS condition. Cisco has released free software updates that
address this vulnerability. A workaround is available to mitigate this
vulnerability."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-ntp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0c1eb72e");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-ntp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2018 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

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
if ( version =~ '^2\\.1([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.2([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.3([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.4([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.5([^0-9]|$)' ) flag++;
else if ( version =~ '^2\\.6([^0-9]|$)' ) flag++;
else if ( version =~ '^3\\.1(\\.[0-9]+)?S$' ) flag++;
else if ( version =~ '^3\\.1(\\.[0-9]+)?SG$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?S$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?SG$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?XO$' ) flag++;
else if ( version =~ '^3\\.2(\\.[0-9]+)?SQ$' ) flag++;
else if (( version =~ '^3\\.3(\\.[0-9]+)?S$' ) && (cisco_gen_ver_compare(a:version,b:'3.3.0S') == -1)) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"ntp multicast", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }

    if (flag)
    {
      buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_msdp_summary", "show ip msdp summary");
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ .* Up", multiline:TRUE, string:buf)) { flag = 1; }
      } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
    }
    else { flag = 0; }
  }
}

if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
