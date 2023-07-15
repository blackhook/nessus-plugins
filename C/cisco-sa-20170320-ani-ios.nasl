#TRUSTED 188dce4d1798c233bc7bc8fac71549e48008b202fe5828b837bd44f4f92ccd55a7976a528d7ceaf23f6cb842b62e21261eb9c59faa7c1e97da050166160864b9febff2b1a00834fb437a3920ccb7c772c7f2f5bbbcd2f2cf33c579a57a3a42456539e85a75bdb6d9b0092d510285adb65d97c03ffb36008c93ef0fd27bd80dddf8124bfc05bed874986a2129c316203e82a3ba433c382510b1a25c164581ffc4ed659abc0f6ac3e5111078b33b523cbf87e9c46dd4126c54be71c33b48f74a5920239d16742d1a6bfac5e744e694e94a855fc6cd7530f9ed864831337f46cbbca8dcaa74befd0572bd941d10bb6302fa3d7397fbf9979f5c57def9503a0155624e7f894b5ec30abd4591e1d8aa45dad7aaee8fec1a4763d0b8ee6ae8ed88d313fce953aa42e24340345fb0e114c9fb59d1bd23aea7af10398572783489a5dcde168f50fe5c4c263ea835db5264805326e804ff5e0ce1eea988098f6441d5ea6b90284be8427ac22cb0f416a5b706863d73e9c588a55f56b73b9002a110212b1eb7c14ad66dac85fc335c79c4d1d4de0f8a73f54be636e74bad32c859ab6c7da7e7decf247f907e600bd7def9304f059279564f2a7972127b33ec1f8a89abf46fc1f50d763cf4c12765483d09745d86ad9302d612381b757cf31c4ed18868ffa76c7acd72e7e17870ff7dd1c561deafa585c1ba688c1cdbae709af5391617d074
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97943);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/01");

  script_cve_id("CVE-2017-3849");
  script_bugtraq_id(96972);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42717");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-ani");

  script_name(english:"Cisco IOS ANI Registrar DoS (cisco-sa-20170320-ani)");
  script_summary(english:"Checks the IOS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS software running
on the remote device is affected by a denial of service vulnerability
in the Autonomic Networking Infrastructure (ANI) registrar feature
due to incomplete input validation of certain crafted packets. An
unauthenticated, adjacent attacker can exploit this issue, via
specially crafted autonomic network channel discovery packets, to
cause the device to reload.

Note that this issue only affect devices with ANI enabled that are
configured as an autonomic registrar and that have a whitelist
configured.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170320-ani
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?206d164a");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Security Advisory
cisco-sa-20170320-ani.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3849");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

affected_versions = [
  '15.3(3)S',
  '15.3(3)S1',
  '15.3(3)S2',
  '15.3(3)S3',
  '15.3(3)S6',
  '15.3(3)S4',
  '15.3(3)S5',
  '15.3(3)S8',
  '15.3(3)S9',
  '15.2(3)E',
  '15.2(4)E',
  '15.2(3)E1',
  '15.2(3)E2',
  '15.2(3)E3',
  '15.2(4)E1',
  '15.2(4)E2',
  '15.2(5)E',
  '15.2(4)E3',
  '15.2(5a)E',
  '15.2(5)E1',
  '15.2(5b)E',
  '15.4(1)S',
  '15.4(3)S',
  '15.4(1)S1',
  '15.4(1)S2',
  '15.4(2)S1',
  '15.4(1)S3',
  '15.4(3)S1',
  '15.4(2)S2',
  '15.4(3)S2',
  '15.4(3)S3',
  '15.4(1)S4',
  '15.4(2)S3',
  '15.4(2)S4',
  '15.4(3)S4',
  '15.4(3)S5',
  '15.4(3)S6',
  '15.4(3)S6a',
  '15.5(1)S',
  '15.5(2)S',
  '15.5(1)S1',
  '15.5(3)S',
  '15.5(1)S2',
  '15.5(1)S3',
  '15.5(2)S1',
  '15.5(2)S2',
  '15.5(3)S1',
  '15.5(3)S1a',
  '15.5(2)S3',
  '15.5(3)S2',
  '15.5(3)S0a',
  '15.5(3)S3',
  '15.5(1)S4',
  '15.5(2)S4',
  '15.5(3)S4',
  '15.5(3)S5',
  '15.5(3)SN',
  '15.6(1)S',
  '15.6(2)S',
  '15.6(2)S1',
  '15.6(1)S1',
  '15.6(1)S2',
  '15.6(2)S2',
  '15.6(1)S3',
  '15.6(1)T',
  '15.6(2)T',
  '15.6(1)T0a',
  '15.6(1)T1',
  '15.6(2)T1',
  '15.6(1)T2',
  '15.6(2)T2',
  '15.6(2)SP',
  '15.6(2)SP1',
  '15.6(2)SN',
  '15.6(3)M',
  '15.6(3)M1',
  '15.6(3)M0a'
];

foreach affected_version (affected_versions)
  if (ver == affected_version)
    flag++;

# Check that ANI is running
if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_run_autonomic","show run | include autonomic");
  if (check_cisco_result(buf))
  {
    if (
      ( !empty_or_null(buf) ) &&
      ( "no autonomic" >!< buf )
    ) flag = 1;
  }
  else if (cisco_needs_enable(buf))
  {
    flag = 1;
    override = 1;
  }
}

if (flag) security_report_cisco(severity:SECURITY_WARNING, port:0, version:ver, bug_id:'CSCvc42717', override:override);
else audit(AUDIT_HOST_NOT, "affected");
