#TRUSTED 29e2bd51d14a1c6035d3aba2dff87a83fd8bee5be9aa9c007823aa675296e54e0d13270e624739c4625b0b4ae57d0a036449c78df2cc63adf6015a7aa8c3796e8ec84077f5e34417639b2a438faa09d356bc35e98251db138fb0739c3f29502a06a801bdecdd5711e64d850b3b896233f124fb20182fcc09d4927c3d9d7fe99eca1706dc0aacf19fea8a0b238135a6c1e6ed553931301e95b237956a33e7921194cc5b19dbf1686844dbe5e2ffe87b0429ff66bec8e367e98e1ad987e7d8607b805d44c93e9bbe3eaaede6395ecb56c9700f958f655fbe19e6dc693f5aa07c1386533f39ffd7d78132c51d56cc77e2a34b559f699eeb97b691ef804a559c1c540db4ac57ca337d9236b23262ab322a56872123580c93ad0e7c5d9f86fc8544ae23f8e835b2d2fa5dcdd26f0c9cdc6d59adb5ba1a37bf31856510c3af185e7b5b0b81f3b5016477c7f72d7790462429ccf74b14981137541ebd733820e1d25074742f98028ba8020270562eeb053f982ff4a6543e16bb01bf5418674c9605262f0624acf5cc423e8b42b196856a9128a547368ad8842830af8e7ce05c2a8d01f7c5af619cd68a6534f4ca3d4587905003e28b3d7fcd9aac87a715305e552d557ab4dc20b709b73244e6c1f4d8ba9f4952e1687038d36703b170e5d28ff8f5a5ead23c2143d03aeaf9e1bae59e6fd11bbbcfb4cd1bdbe15ca9185e99c70d1a9293
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90861);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2016-1384");
  script_xref(name:"CISCO-BUG-ID", value:"CSCux46898");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20160419-ios");

  script_name(english:"Cisco IOS NTP Subsystem Unauthorized Access (cisco-sa-20160419-ios)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by an unauthorized access
vulnerability in the NTP subsystem due to a failure to check the
authorization of certain NTP packets. An unauthenticated, remote
attacker can exploit this issue, via specially crafted NTP packets, to
control the time of the remote device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160419-ios
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8965288b");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCux46898.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-1384");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2016-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

flag = 0;
override = 0;

ver = get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Check for vuln version
# Below are from CVRF
if ( ver == '15.1(1)S' ) flag++;
if ( ver == '15.1(1)S1' ) flag++;
if ( ver == '15.1(1)S2' ) flag++;
if ( ver == '15.1(2)S' ) flag++;
if ( ver == '15.1(2)S1' ) flag++;
if ( ver == '15.1(2)S2' ) flag++;
if ( ver == '15.1(3)S' ) flag++;
if ( ver == '15.1(3)S0a' ) flag++;
if ( ver == '15.1(3)S1' ) flag++;
if ( ver == '15.1(3)S2' ) flag++;
if ( ver == '15.1(3)S3' ) flag++;
if ( ver == '15.1(3)S4' ) flag++;
if ( ver == '15.1(3)S5' ) flag++;
if ( ver == '15.1(3)S5a' ) flag++;
if ( ver == '15.1(3)S6' ) flag++;
if ( ver == '15.5(3)M' ) flag++;
if ( ver == '15.5(3)M0a' ) flag++;
if ( ver == '15.5(3)M1' ) flag++;
if ( ver == '15.5(1)S' ) flag++;
if ( ver == '15.5(1)S1' ) flag++;
if ( ver == '15.5(1)S2' ) flag++;
if ( ver == '15.5(1)S3' ) flag++;
if ( ver == '15.5(1)S4' ) flag++;
if ( ver == '15.5(2)S' ) flag++;
if ( ver == '15.5(2)S1' ) flag++;
if ( ver == '15.5(2)S2' ) flag++;
if ( ver == '15.5(2)S3' ) flag++;
if ( ver == '15.5(3)S' ) flag++;
if ( ver == '15.5(3)S0a' ) flag++;
if ( ver == '15.5(3)S1' ) flag++;
if ( ver == '15.5(3)S1a' ) flag++;
if ( ver == '15.5(3)SN' ) flag++;
if ( ver == '15.5(2)T' ) flag++;

# NTP check
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  buf = cisco_command_kb_item("Host/Cisco/Config/show_ntp_status", "show ntp status");
  # Check for traces of ntp
  if (check_cisco_result(buf))
  {
    if (
      "%NTP is not enabled." >< buf &&
      "system poll" >!< buf &&
      "Clock is" >!< buf
    ) audit(AUDIT_HOST_NOT, "affected because NTP is not enabled");
  }
  else if (cisco_needs_enable(buf)) override = 1;
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Cisco bug ID      : CSCux46898' +
      '\n  Installed release : ' + ver +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
}
else audit(AUDIT_HOST_NOT, "affected");
