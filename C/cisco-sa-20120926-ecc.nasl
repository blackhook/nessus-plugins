#TRUSTED 2d14390b5553047a8aaebcb5dd4b490d6f804c6692ce0c196fa68bb6343c976537258953a7282c69b5e8d0dcedeb7e945823917dd672fbb280b1e70f493f3bec3f838d94799f7f6489d5a67d8257658f452358e7c942b3ecbf0a3948049dd7f6201e4bd106ca0288a8d9c39d2aa9054ec7fe749a93465aad86260a2aa283363545999ae11278d02fcf2c5a59d4f65752d10b46b6fbc0c28fc42e7a6cc5f4774263fc5599f1a902ed079e5318d11fdd6529378443bfdda8d78ba2ef06e622bc5d9cf4fab2e46c2e72e39c702a3ba284d221d06bc35fce1d84daa61a06bfa80792eadd4bf8fb10f7290fb1b2c28e6cb79b3c83e896e72dd0885b80f18024cee936b1520bfe6e3bb33a6608ae56781baf2094acd80aa26d04ae0a2593a3c1f40819da3a7c9a151ed1cf868f5c85026d2c57f4f47c8d3d7d428fd534827861491ca4c3620cc43dc7722a86cdd417fc25bcb76c96bd1d4c04b40d495637d38c556fe47dde05f42f386b1d242d519838d0cc2456453541590c072f326e41d3e3ff6956b15e51382eee0f442700a24aa1cdf81ff7469d398bb28a43cb0b80d611da81ca60a60b5d39200e1053e1ebb5ed713919bef2a6cf1fd27cca1d3aa83a055cf356da2cb2a00181931a629c14c75346a12334b1ab317459c95f46608fff802cafc13206eff865ab6aff73c7514dbddccb77aaf5af9866f4c6c2b58b98eb793cc006
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20120926-ecc.
# The text itself is copyright (C) Cisco
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(67204);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id("CVE-2012-4622");
  script_bugtraq_id(55701);
  script_xref(name:"CISCO-BUG-ID", value:"CSCty88456");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20120926-ecc");
  script_xref(name:"IAVA", value:"2012-A-0154-S");

  script_name(english:"Cisco Catalyst 4500E Series Switch with Cisco Catalyst Supervisor Engine 7L-E Denial of Service Vulnerability (cisco-sa-20120926-ecc)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Catalyst 4500E series switch with Supervisor Engine 7L-E contains
a denial of service (DoS) vulnerability when processing specially
crafted packets that can cause a reload of the device. Cisco has
released free software updates that address this vulnerability.
Workarounds that mitigate this vulnerability are not available."
  );
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20120926-ecc
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3693a5e7"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20120926-ecc."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/08");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2020 Tenable Network Security, Inc.");
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
if ( version == '15.0(2)XO' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{

  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_module", "show module");
    if (check_cisco_result(buf))
    {
      if (preg(pattern:"WS-X45-SUP7L-E ", multiline:TRUE, string:buf)) { flag = 1; }
    } else if (cisco_needs_enable(buf)) { flag = 1; override = 1; }
  }
}


if (flag)
{
  security_hole(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
