#TRUSTED 732346eb895ebd2789ff680fb3577ee27aaf8eed2aa8cc1a183ee0b50f4189f6c5271b6817e940b4e69fd12a9955904886df65fe7d56dd3b92fac0d81984e42d73ada34b92c959c7414783f89876a847eb47c1ee560383889d5512a433be1a7c3179719ac86ac3199c06f260565484b5c0506b614e8583fd1410e380e269c185c3eb410ff2cb1358489d2cd05ad4b3b52ba6c3026a4aa1cf0795247a3f46454ebf4d7e93aade47b757b49b3fd35a2b626558920d3cd1238edc271b280f0173be0871b1dd00774649fba2c18c14b4bd01a0f1935ca5de720ebbf96699aab5ed64530e4c2f31a6ad70a5713d3a839adea603829f43e58f6932c55fb91cb5902aaec1711e2ce0b6efcd296d42bf21dbcf52f5c20c0efd2f9df3f3b00a83893d3cc069dd6fe491919223a9a70f36ba5d69055cf102f7d70fcb47ccdb2e000f998df3f3763d8bb5079785441303d4c959be7411425b8b1b465bc00c40e4ea4fb854b10d8028bf6f739ddad6869affd4ad26750e489758b366ad8615ea07d247f8e0a84538b6e1b309656f0870bd46dd66a662637db90aabcd21df8ecd6226b9557770e41295624e2950c69792dffa21874c0fd73b85be5de0e0d25be6491543e3acbed3ce089d3d9f3ce6928efbea674228e86fb24321d494f0b2397530a2c8cf0af82024c256e42388c6ef4e83793f1c166255ecdaf32c9671335a30af5dea567b70
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86248);
  script_version("1.11");
  script_cvs_date("Date: 2019/11/20");

  script_cve_id("CVE-2015-6282");
  script_xref(name:"CISCO-BUG-ID", value:"CSCut96933");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20150923-iosxe");

  script_name(english:"Cisco IOS XE Network Address Translation and Multiprotocol Label Switching DoS (CSCut96933)");
  script_summary(english:"Checks IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing vendor-supplied security patches.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco IOS XE device is missing vendor-supplied security
patches, and is configured for Network Address Translation (NAT)
and/or Multiprotocol Label Switching (MPLS). It is, therefore,
affected by a flaw in the NAT and MPLS services due to improper
processing of IPv4 packets. An unauthenticated, remote attacker can
exploit this, via a crafted IPv4 package, to cause the device to
reboot.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20150923-iosxe
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?280014a1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCut96933.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
model   = get_kb_item_or_exit("Host/Cisco/IOS-XE/Model");

if (
  !(
      "ASR1k" >< model ||
      model =~ '^ASR 10[0-9][0-9]($|[^0-9])' ||
      "ISR4300"  >< model ||
      "ISR4400"  >< model ||
      "CSR1000V" >< model
  )
) audit(AUDIT_HOST_NOT, "an affected model");

flag     = FALSE;
override = FALSE;

if (version =='2.1.0') flag++;
if (version =='2.1.1') flag++;
if (version =='2.1.2') flag++;
if (version =='2.1.3') flag++;
if (version =='2.2.1') flag++;
if (version =='2.2.2') flag++;
if (version =='2.2.3') flag++;
if (version =='2.3.0') flag++;
if (version =='2.3.0t') flag++;
if (version =='2.3.1t') flag++;
if (version =='2.3.2') flag++;
if (version =='2.4.0') flag++;
if (version =='2.4.1') flag++;
if (version =='2.4.2') flag++;
if (version =='2.4.3') flag++;
if (version =='2.5.0') flag++;
if (version =='2.5.1') flag++;
if (version =='2.5.2') flag++;
if (version =='2.6.0') flag++;
if (version =='2.6.1') flag++;
if (version =='2.6.2') flag++;
if (version =='2.6.2a') flag++;
if (version =='3.1.0S') flag++;
if (version =='3.1.1S') flag++;
if (version =='3.1.2S') flag++;
if (version =='3.1.3S') flag++;
if (version =='3.1.4S') flag++;
if (version =='3.1.4aS') flag++;
if (version =='3.1.5S') flag++;
if (version =='3.1.6S') flag++;
if (version =='3.2.0S') flag++;
if (version =='3.2.1S') flag++;
if (version =='3.2.2S') flag++;
if (version =='3.2.3S') flag++;
if (version =='3.3.0S') flag++;
if (version =='3.3.1S') flag++;
if (version =='3.3.2S') flag++;
if (version =='3.4.0S') flag++;
if (version =='3.4.0aS') flag++;
if (version =='3.4.1S') flag++;
if (version =='3.4.2S') flag++;
if (version =='3.4.3S') flag++;
if (version =='3.4.4S') flag++;
if (version =='3.4.5S') flag++;
if (version =='3.4.6S') flag++;
if (version =='3.5.0S') flag++;
if (version =='3.5.1S') flag++;
if (version =='3.5.2S') flag++;
if (version =='3.6.0S') flag++;
if (version =='3.6.1S') flag++;
if (version =='3.6.2S') flag++;
if (version =='3.7.0S') flag++;
if (version =='3.7.1S') flag++;
if (version =='3.7.2S') flag++;
if (version =='3.7.3S') flag++;
if (version =='3.7.4S') flag++;
if (version =='3.7.5S') flag++;
if (version =='3.7.6S') flag++;
if (version =='3.7.7S') flag++;
if (version =='3.8.0S') flag++;
if (version =='3.8.1S') flag++;
if (version =='3.8.2S') flag++;
if (version =='3.9.0S') flag++;
if (version =='3.9.1S') flag++;
if (version =='3.9.2S') flag++;
if (version =='3.10.0S') flag++;
if (version =='3.10.01S') flag++;
if (version =='3.10.0aS') flag++;
if (version =='3.10.1S') flag++;
if (version =='3.10.2S') flag++;
if (version =='3.10.3S') flag++;
if (version =='3.10.4S') flag++;
if (version =='3.10.5S') flag++;
if (version =='3.11.0S') flag++;
if (version =='3.11.1S') flag++;
if (version =='3.11.2S') flag++;
if (version =='3.11.3S') flag++;
if (version =='3.11.4S') flag++;
if (version =='3.12.0S') flag++;
if (version =='3.12.1S') flag++;
if (version =='3.12.2S') flag++;
if (version =='3.12.3S') flag++;
if (version =='3.13.0S') flag++;
if (version =='3.13.1S') flag++;
if (version =='3.13.2S') flag++;
if (version =='3.14.0S') flag++;
if (version =='3.14.1S') flag++;
if (version =='3.14.2S') flag++;
if (version =='3.14.3S') flag++;
if (version =='3.14.4S') flag++;
if (version =='3.15.0S') flag++;

if (get_kb_item("Host/local_checks_enabled"))
{
  # Look for NAT
  if (flag)
  {
    flag = 0;
    buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-include-ip-nat", "show running-config | include ip nat");
    if (check_cisco_result(buf))
    {
      if (
        "ip nat inside" >< buf ||
        "ip nat outside" >< buf
      )
        flag = TRUE;
    }
    else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
  }

  # Look for MPLS
  buf = cisco_command_kb_item("Host/Cisco/Config/show-running-config-interface", "show running-config interface");
  if (check_cisco_result(buf))
  {
    pieces = split(buf, sep:"interface", keep:FALSE);
    foreach piece (pieces)
    {
      if (
        "mpls ip" >< piece &&
        ("ip nat inside" >< piece || "ip nat outside" >< piece)
      ) { flag = TRUE; override = FALSE; }
    }
  }
  else if (cisco_needs_enable(buf)) { flag = TRUE; override = TRUE; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCut96933' +
      '\n  Installed release : ' + version +
      '\n';
    security_hole(port:0, extra:report+cisco_caveat(override));
  }
  else security_hole(port:0, extra:cisco_caveat(override));

}
else audit(AUDIT_HOST_NOT, "affected");
