#TRUSTED 1550feb7053338409bc2e5280b68a00982c3e7ed1312c352d18ad8546d528be18d385708386b64e5cb5c9d4fcde6b919c51803f400ce7b13a25ad95ff20aa5279c8aefb57abccdb95fd3befec2bf7578a0830fc5bed5d76fd4d3030e90ba057d2b7a683a6fb88b5cf8055c667b49ee31893b299636a0244bb1362b28a26e696d27f0a8418eecfb1ada44d620854a633ec9669114bf9ee3ba0d00dd377becf53198d791925ec63a52e70b40d90f5aa91e9515e15d3ec98938d83e1529c58a93c937319ae737677b682a58750c9132bb2d90032946f24ffd274effc37fced2ce87f53c8cd3cd114b0e2b8db62e7a656431f1335e62b755236113d5f65d72770d0bd4df15c406ed91983f53fb4911873e957bff28d89dbb3b9e9cc19c06e4b422a19bdc63cfb1745dd5da2f46728f85c71ca2c106dc0e8c85189ec2321498adf69e7e98b88741b146965e723754c4d42a4f0b87a17e0cbbefe5a32ea81390a8d2ac3ddfd5539f6483914595a6cc6bc21550fdcef81323fbb7ed9491ad926909bf30e072ebabe863f20627dbc984126867cf8a9b660bcb073fd9caa6e3a560269975999e33e6a510bb68df5e2de5df9188f1d8d9d108df520b9d582248e7b09977301c40c394d2a3590bcaef7ac64465d6b8fc71fc65a81638f7ba2085c011e42260e748be2e9d7e7eee8c79ae953b469c999bb4b06ff2de569e28727740eafea6c6
#TRUST-RSA-SHA256 39b25d648b02c7dca8a3e8beaeb3a24f43fcea999f88e7191b454e748d84a90422f73e684174d4790629f9dd78730ff113d80b269a1a49a276d002b2d4e933afaafb349059698e1032be960a2a78f2c0ec37b6007b0fbdc00ca6cff75946c76cea3abbe2dbd58ca5af362731446bbf0618ed89818c03eda85dd74ea69c2fe919eda89bf35eddeac427b80be0736056de0921291805fa12004e1a9c4be44c4018fa4e6bc64049944a48defebe9330cfc62929b70755e0b88eee249aace430c31c771f5c85dbf1c6a8ae28df44daf8d50b918de7dd7b77c18a4eb4c1fe2927bc0e889b46b3ae62d070525ace3877515715daa01ac9f1b377695f82b8db9957ea746a8ea04cf06c6ef6e218f951adbd65f972d1fab1551df9de0852d89b7f14a54b3b8d3b1204081f99603a407386f109cfab2f637ae8a7fe5aecda739dc6550be46f21bd1f69951d6541e9666a59c2234a75956589f9635999bd7afbd7c18bc77aa1afe607010253874defddedc7bdd8c5e8868e16eef9803336eea98ac7790e1f97495a692df572732006cd803d850d83ae69bc1f106d5aea69354a156cedf5edc01859fa24b45bde81e253e313e82d777d02bfafc9d61df70923a3776f651e449832d5fff119c002ca23e1220f22b6ee1300b556c07b6621fa51efe6131d6c0facc4e7b987712bdde2312c76da35735922b8f61008f1d92a6390fe1ae50cba5c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(133723);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/06");

  script_xref(name:"IAVT", value:"0001-T-0559");

  script_name(english:"Cisco Software Maintenance Update Enumeration");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate installed Cisco Software Maintenance Updates on the remote host.");
  script_set_attribute(attribute:"description", value:
"It is possible to enumerate the installed Cisco Software Maintenance Updates on the remote Cisco device using the
command 'show install active'.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl", "cisco_nxos_version.nasl");
  script_require_ports("Host/Cisco/IOS-XR/Version", "Host/Cisco/NX-OS/Version");

 exit(0);
}

include('cisco_kb_cmd_func.inc');

# Lets get the SMU list first
buf = cisco_command_kb_item("Host/Cisco/Config/show_install_active", "show install active");

# Now check if we failed to get the patches
if(!check_cisco_result(buf)) exit(0, "Unable to retrieve patch information.");

# Patches usually have the following pattern:
# disk0:hfr-px-4.3.2.CSCul20020-1.0.0
# disk0:hfr-px-4.3.2.CSCul26557-1.0.0
# disk0:hfr-px-4.3.2.CSCun00853-1.0.0
# disk0:hfr-px-4.3.2.CSCui74251-1.0.0
# But nxos.CSCvr09175-n9k_ALL-1.0.0-<NX-OS_Release>.lib32_n9000 is also seen
pat = "\s*(disk[0-9]+:|flash:|nxos\.)([A-z0-9.\-_]+)";

split = split(buf, keep:true);

patches = '';
report = '';

foreach line (split)
{
  match = pregmatch(pattern:pat, string:line);

  if(isnull(match)) continue;

  if(match[2] >< patches) continue;

  report += '  - ' + match[2] + '\n';
  patches += match[2] + ',';
}

if (empty_or_null(patches))
  exit(0, "Unable to retrieve patch information.");
else
  set_kb_item(name:'Host/Cisco/SMU', value:patches);

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
