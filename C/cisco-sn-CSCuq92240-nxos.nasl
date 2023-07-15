#TRUSTED 6df7c89d303f870fce8a0e296f1f7c8c3293d301c1788bb28d05874248463e01782db4522ac622682f464629a7b8414b9c286e97b60fc786f583ef6f1c485af0070c1afdb1b721512e47e97471421b2a2919c4db0e76e2efc6102f779e8d9f16063671236de03c1fe58fa9ab521f2a1a6dbd4595e6ef936fb563f0e886b59dfe2a33107f353e6c4996f8087da587a57b3d03ffc0b3b7498a914604a33cddf6718bd0ab5e64b5efc17dcaec9cfb56ac61b194a5a8320378438bbb4d888457f70675be187580b5b780d678abedc4aecfa95935413152eac4355e6684725528920ed69d962e473d76d77fcfc5d977dbfdefd44dcce41766f51d1b5b69556dbaa3d6a2ed4f7e612c02d3b9ba2e29e0d1d9df845fab61775b0f38e26558bf92ef5dbab0414aca4bcd06d00c56660a8e8a29447d9231df9e49122490e4cc295c4490b73af5f97da4acbe0d8d79f515534fe216b54089c7eb064192ec4633643f3f11fb677b6ebf6ca74ba39f4e9d20504c4988b4890b13dbe5661531fd74c0a94a60f0637f553e522c66b9fe0b6b4be1cab80ffcf842cbb8034f976a40d033ca4ba73167dae7597acd17d17db833e2f20fcbc93630500ccc63aa51a6955a51404637459af04728149a0dd2b1bf9312fbe81d8057defc018f32d8ef82fd917eafd7a5b138f5a4690229b6c247887845136223b5dec1ec8b153537b169a31dfa81357ec6
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82666);
  script_version("1.10");
  script_cvs_date("Date: 2019/11/22");

  script_cve_id("CVE-2015-0686");
  script_bugtraq_id(73895);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuq92240");

  script_name(english:"Cisco Nexus 9000 Series Platform Manager Service DoS");
  script_summary(english:"Checks the NX-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The remote Cisco Nexus device is affected by a denial of service
vulnerability in the Platform Manager service, part of the SNMP
subsystem, when the High Availability (HA) policy is configured to
Reset. A remote, authenticated attacker can exploit this to trigger a
device reload.");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=38193");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCuq92240.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2015-0686");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/09");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2015-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Device", "Host/Cisco/NX-OS/Model");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

device  = get_kb_item_or_exit("Host/Cisco/NX-OS/Device");
model   = get_kb_item_or_exit("Host/Cisco/NX-OS/Model");

# only affects nexus 9000 series systems
if (device != 'Nexus' || model !~ '^9[0-9][0-9][0-9]([^0-9]|$)') audit(AUDIT_HOST_NOT, "affected");

version = get_kb_item_or_exit("Host/Cisco/NX-OS/Version");

flag = 0;
override = 0;

if (version == "6.1(2)I2(3)") flag++;

if (flag && get_kb_item("Host/local_checks_enabled"))
{
  flag = 0;
  buf = cisco_command_kb_item("Host/Cisco/Config/show_version",
                              "show version");
  if (check_cisco_result(buf))
  {
    if (!preg(multiline:TRUE, pattern:"hap reset", string:buf)) { flag++; }
  } else if (cisco_needs_enable(buf)) { flag++; override++; }
}

if (flag)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Model             : ' + device + ' ' + model +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 6.1(2)I3(1)' +
      '\n';
    security_warning(port:0, extra:report + cisco_caveat(override));
  }
  else security_warning(port:0, extra:cisco_caveat(override));
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
