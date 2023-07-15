#TRUSTED 4bcb6b220d012299bc48cfe01db3e50a3a486401fec33fe61b2ed1e12fba7914e15ca0ebf17fbf88dd5cc3090bc61a7b1f07a721128453a4bd76de25fc1c932e101e393769e43ec50bbd223fbf1c8c4a950ab95fb8f5365bd7cbda05f665c996a97a4bb3f5fe7ca6482678e9eb9729fa8e76cc341e04c1f277cbf39b00ad46744f9d4293fa2b0f456318831247ca8aec054a8c566620cccebe287859006e30972df6cc0fe0c7f7448d12a655fb1b5bdcd817fe905c3bc08e3a45bd3251e0e3cb55d1cde5e601fa125add9f7128a6a17ed3ca6885158c52731cf5c2d8946230ef7ec7f45ece5ba52db08cd3fcef8190f14306ced74c5daf7c3cd9ff42821d5cb6f0c79ae32b1a43026fd3087c844047272015b1e4aa8e885ebc8c8c12a19b3c35dd1ea3c87b86560c1d85cb90221ec4bc11caa83aed4120cbb40f9a65054e7ef6769f2229eb1a52620ebb357077885fa7ea4308f50a1db9490805ee5a5fdc4d122ae93a38a6ee86f14ddc370689d215e21b8165d64b076e9b3b6f0f16529414a197748e97bbac956960cc95a3f04b124e3026e2cc771782774bfda89e6f4e343a1615960099196958059c3dbaabd05af0161bda18e462ff7080c9014268f264c8429e4554ff1eed3b8402950cef394c1d80fb2c21bdd436ed2c9ee3056d1e35e433e5f74bc564325b404275eab3fd9ade00377effee6c0aa158c50e00fa782cb3
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130327-smartinstall.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(65891);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/11/15");

  script_cve_id("CVE-2013-1146");
  script_bugtraq_id(58746);
  script_xref(name:"TRA", value:"TRA-2013-03");
  script_xref(name:"CISCO-BUG-ID", value:"CSCub55790");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130327-smartinstall");

  script_name(english:"Cisco IOS Software Smart Install Denial of Service Vulnerability (cisco-sa-20130327-smartinstall)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Smart Install client feature in Cisco IOS Software contains a
vulnerability that could allow an unauthenticated, remote attacker to
cause a denial of service (DoS) condition on an affected device.
Affected devices that are configured as Smart Install clients are
vulnerable. Cisco has released free software updates that address this
vulnerability. There are no workarounds for devices that have the
Smart Install client feature enabled."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2013-03");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130327-smartinstall
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?74d7638e"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20130327-smartinstall."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

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
if ( version == '12.2(55)EX' ) flag++;
if ( version == '12.2(55)EX1' ) flag++;
if ( version == '12.2(55)EX2' ) flag++;
if ( version == '12.2(55)EX3' ) flag++;
if ( version == '12.2(55)EY' ) flag++;
if ( version == '12.2(55)EZ' ) flag++;
if ( version == '12.2(55)SE' ) flag++;
if ( version == '12.2(55)SE1' ) flag++;
if ( version == '12.2(55)SE2' ) flag++;
if ( version == '12.2(55)SE3' ) flag++;
if ( version == '12.2(55)SE4' ) flag++;
if ( version == '12.2(55)SE5' ) flag++;
if ( version == '12.2(55)SE6' ) flag++;
if ( version == '12.2(58)EX' ) flag++;
if ( version == '12.2(58)EY' ) flag++;
if ( version == '12.2(58)EY1' ) flag++;
if ( version == '12.2(58)EY2' ) flag++;
if ( version == '12.2(58)EZ' ) flag++;
if ( version == '12.2(58)SE' ) flag++;
if ( version == '12.2(58)SE1' ) flag++;
if ( version == '12.2(58)SE2' ) flag++;
if ( version == '15.0(1)EY' ) flag++;
if ( version == '15.0(1)EY1' ) flag++;
if ( version == '15.0(1)EY2' ) flag++;
if ( version == '15.0(1)SE' ) flag++;
if ( version == '15.0(1)SE1' ) flag++;
if ( version == '15.0(1)SE2' ) flag++;
if ( version == '15.0(1)SE3' ) flag++;
if ( version == '15.0(2)SE' ) flag++;
if ( version == '15.1(1)SG' ) flag++;
if ( version == '15.1(1)SG1' ) flag++;
if ( version == '15.1(1)SG2' ) flag++;
if ( version == '15.1(1)SY' ) flag++;
if ( version == '15.1(4)GC' ) flag++;
if ( version == '15.2(1)GC' ) flag++;
if ( version == '15.2(1)GC1' ) flag++;
if ( version == '15.2(1)GC2' ) flag++;
if ( version == '15.2(2)GC' ) flag++;
if ( version == '15.2(3)GC' ) flag++;
if ( version == '15.2(3)GCA' ) flag++;
if ( version == '15.2(3)XA' ) flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
    if (check_cisco_result(buf))
    {
      if ( (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf)) &&
         (!preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient\s+\(SmartInstall disabled\)", string:buf)) ) { flag = 1; }
    }
    else if (cisco_needs_enable(buf)) {flag = 1; override = 1; }
  }
}

if (flag)
{
  report +=
    '\n  Cisco Bug ID        : CSCub55790' +
    '\n    Installed release : ' + version + '/n';
  security_hole(port:0, extra:report + cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
