#TRUSTED 6ff089bd24e5135689e3ee61fa57f920b72c73f948a8a57d3d5358a079770b9728aa3d566774160a7fd1aebea05889b8f203bafe0694ca3ed97be67ca7324732ae6d2b614f9f5036102fb15978c05aab4c901c7e55fa932a9d61ab85b4e3cd78cacaf11a141b2b7bbef6a36291d1c6bba6b854d124aa8d8ce55d507eea5ca6bf2eed2ff34a37c823d1d5876a9bc1b5997a29079e124f91e090732451c5d8709397f16624036858a86e25d5f2ac575a52068f998ddcd79a24b8802426d8fc5c9f9c3864fdd7929ca133b63180d9e90b7f981f1b63d7ed37cfc66cf4f6ab4d06a2632b41e14b8d651f0fd9f76a4cd6932ea89f21f81d964a33dd80954421560007c081af957f404c1b5b17596e9124695f8fd115848a977b28ae94e674b18f3273f5d55a013bb1bd3ae440f44276b8f2aa55e183fec9d19a072b2e4ebafc556a1ee7d3e212b5e9a740ae915bd5ed1043b3e07c5a445a738bbaa2c3c506f739ec78d7ed6de123cb332e7359a10118b15c022615472bcc347f9607be75820d9027f1ae3267a3eeee4d3e6da46e26ff48f2df6a4e36a0d5da262528c893bad24fcc0fdbca72c37b1054d5c30c455ce247e956aaeef157d2267351abcb84cb62fd354b2fff582da371390989350919a31db849f03f5e707dff32cb629b292d5ac23983380bee5d7c47144fe37810a3f7fb140bb1d781259fbcbb573703697837f3023e
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97944);
  script_version("1.8");
  script_cvs_date("Date: 2019/11/13");

  script_cve_id("CVE-2017-3849");
  script_bugtraq_id(96972);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvc42717");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20170320-ani");

  script_name(english:"Cisco IOS XE ANI Registrar DoS (cisco-sa-20170320-ani)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Cisco IOS XE software
running on the remote device is affected by a denial of service
vulnerability in the Autonomic Networking Infrastructure (ANI)
registrar feature due to incomplete input validation of certain
crafted packets. An unauthenticated, adjacent attacker can exploit
this issue, via specially crafted autonomic network channel discovery
packets, to cause the device to reload.

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

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2017-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

ver = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");

flag = 0;
override = 0;

affected_versions = [
  '3.10.0S',
  '3.10.1S',
  '3.10.2S',
  '3.10.3S',
  '3.10.4S',
  '3.10.5S',
  '3.10.6S',
  '3.10.2tS',
  '3.10.7S',
  '3.10.1xbS',
  '3.10.8S',
  '3.10.8aS',
  '3.11.1S',
  '3.11.2S',
  '3.11.0S',
  '3.11.3S',
  '3.11.4S',
  '3.12.1S',
  '3.12.2S',
  '3.12.3S',
  '3.12.0aS',
  '3.12.4S',
  '3.13.0S',
  '3.13.1S',
  '3.13.2S',
  '3.13.3S',
  '3.13.4S',
  '3.13.5S',
  '3.13.2aS',
  '3.13.0aS',
  '3.13.5aS',
  '3.13.6S',
  '3.13.6aS',
  '3.14.0S',
  '3.14.1S',
  '3.14.2S',
  '3.14.3S',
  '3.14.4S',
  '3.15.0S',
  '3.15.1S',
  '3.15.2S',
  '3.15.1cS',
  '3.15.3S',
  '3.15.4S',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.16.0S',
  '3.16.1S',
  '3.16.1aS',
  '3.16.2S',
  '3.16.0cS',
  '3.16.3S',
  '3.16.2bS',
  '3.16.3aS',
  '3.16.4S',
  '3.16.4aS',
  '3.16.4bS',
  '3.16.5S',
  '3.16.4dS',
  '3.17.0S',
  '3.17.1S',
  '3.17.2S ',
  '3.17.1aS',
  '3.17.3S',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.18.0aS',
  '3.18.0S',
  '3.18.1S',
  '3.18.2S',
  '3.18.3vS',
  '3.18.0SP',
  '3.18.1SP',
  '3.18.1aSP',
  '3.18.1bSP',
  '3.18.1cSP',
  '3.9.0E',
  '3.9.1E'
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
