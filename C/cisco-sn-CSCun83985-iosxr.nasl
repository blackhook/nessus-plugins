#TRUSTED 42d0a1df9e682a8f04ec8bb5449bc2b29b62e0f2150584eba522fba7c772c9d69fbd95a8b2e8f1431a898af8f1d3e284656a97ddde76d3adbf9b27467edda660e62edba972fa15470dd23a923c0a83b3efdee3cc3aff9354b7b6aa5a656ec136f6e3fb9f53723598f1ee98bb02cfa30e850310d3b2160db4b614cd2024988f335e9d7d6996279511383e4c38a955ece6890c07c06fab98074fafb3dfe9512dd3bbddf9f3e585c734a46cee129248c2da128a2bc8c3d8c63a144d37346e28b3971604809cf5cc235b49b271130b9f0a1d363d21358de3be9f14ffea859e528b70f6257f9b272a1b3ad4124d28abf9b66d9d79446ea9adb46e7d819106ab484ec1c4b126ad30760197371f989090db3cf8089e84452ed1d5f73d08478d152b00689fc174bd1d48aaba535a41836e34f7054f550d9a2cf116b6414271cc66470c16031d94674e3cd5a3756db7e0b51d5fcc5942275c1e54779f3f8ca9cccde713ee0c93516dd3a20e9ce3c4d0f14c1c2caa8dd93abf9d6147f130237e4f0c9372e9e9041a2f3c814bae70d83f5297e2a9d9fec47f8227d3e2a771aa5a3a1dc9a46b6678f971c6a6266105de63d6c8baf99f39f073a8368805afccd4e6ef82fabe013d70b9350b494affdbf2e9f1e70a90d757213ebaab4a47c847989f742943b874c3d247c2911a993387b7c8b2f69466cf5d7571d24f90e007b91c62fd699c4bb0
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77051);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/08");

  script_cve_id("CVE-2014-3308");
  script_bugtraq_id(68351);
  script_xref(name:"CISCO-BUG-ID", value:"CSCun83985");

  script_name(english:"Cisco IOS XR Software Static Punt Policer DoS (CSCun83985)");
  script_summary(english:"Checks the IOS XR version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the version of Cisco IOS XR
running on the remote host is affected by a denial of service
vulnerability due to a missing static punt policer. A remote,
unauthenticated attacker can cause the device to lock up by rapidly
sending specially crafted packets.

Note that this issue only affects Trident-based line cards on Cisco
ASR 9000 series routers.");
  # https://tools.cisco.com/security/center/viewAlert.x?alertId=34843
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f220f425");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewAlert.x?alertId=34843");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patch referenced in Cisco Bug ID CSCun83985.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3308");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2014-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

# check model
model = get_kb_item("CISCO/model");
if (!isnull(model) && model !~ "ciscoASR9[0-9]{3}")
  audit(AUDIT_HOST_NOT, "affected");
if (isnull(model))
{
  model = get_kb_item_or_exit("Host/Cisco/IOS-XR/Model");
  if ("ASR9K" >!< model) audit(AUDIT_HOST_NOT, "affected");
}


version = get_kb_item_or_exit("Host/Cisco/IOS-XR/Version");

# A patch is available for version 5.1.2
if (report_paranoia < 2 && version == "5.1.2") audit(AUDIT_PARANOID);

if ( version !~ "^5\.1\.[0-2]$" )
  audit(AUDIT_INST_VER_NOT_VULN, 'Cisco IOS XR', version);

override = FALSE;

port = get_kb_item("Host/Cisco/IOS-XR/Port");
if(empty_or_null(port))
  port = 0;

if (get_kb_item("Host/local_checks_enabled"))
{
  flag = FALSE;

  buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
  if (check_cisco_result(buf))
  {
    pat = "A9K-(40GE-L|40GE-B|40GE-E|4T-L|4T-B|4T-E|8T/4-L|8T/4-B|8T/4-E|2T20GE-L|2T20GE-B|2T20GE-E|8T-L|8T-B|8T-E|16T/8-B)";
    if (preg(multiline:TRUE, pattern:pat, string:buf)) flag = TRUE;
  }
  else if (cisco_needs_enable(buf)) override = TRUE;

  if (!flag && !override) audit(AUDIT_HOST_NOT, "affected because the device does not use any Trident-based line cards.");
}

if (report_verbosity > 0)
{
  report =
    '\n  Cisco Bug ID      : CSCun83985' +
    '\n  Installed release : ' + version + 
    '\n';
  security_warning(port:port, extra:report+cisco_caveat(override));
}
else security_warning(port:port, extra:cisco_caveat(override));
