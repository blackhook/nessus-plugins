#TRUSTED 795312c769de50c9416a1ccf73ab3408eb8acbc24117abc4cda6f6a1693d5c059eb3a258eb9f16a4754efcda991f2e11a5e57721d46e919ecc5d9c0c0af3cdbd63ab96847c3d17d567213b2905b0f2803af1b4e0eae19d3a661048824f6ad625190ce5c0acde3162d3575ccbc2027ab5efa2de7f7b3263c10910aaddef3f67cc1362655e0ab282edf4ae07122d729fc58573e8be5b84a8c0331630996da7aa20199f2a8bbc6e7c9dbe8e5e609d03da5c2cf4feac073705e1ebd254983e97ff3c07261eddb504a3a41497896fe52b26cea39b7a6f5394a79adcda41eb07bf56f96f9ac4f87fab99f41fea542b4153888cce8b622d542e1188d2a13daf7cd170f819be2701161003759fbaf347ad49d1ef2604aa84699bf5c7aec1b46f7cb4768f9641eb71bc8518247b9e94a258d1a627790ae588d63f20ed82e9c76b4f7add2497178320317fa6dd29d0f6f0c26abd0c17defc0ef55be020d50834728e3aeb752ee6ea07d5b03f41dc8369e6a20f5002b5e58f5875f6c666d29651b927db3e326659a28aae04a32744642de57aacce1f59e667cc127926a867772641aff8df6391a3a2d11fccb778861d62613a29c8ce6f86102f8a46f8f81248b726f2bf4d84b037f3a191445443d24476c042d9e48897a9379de1c9f2a36210ee80eab13907330262cfec08c46b6f65992888caebfe402c46a9112ebbccda72487e107a8c85
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104040);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-10619");
  script_xref(name:"JSA", value:"JSA10821");

  script_name(english:"Juniper Junos DoS Vulnerability (JSA10821)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a vulnerability in the express path feature that could
cause the flowd process to crash.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10821&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40868300");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10821.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ '^(SRX(14|34|36|54|56|58[0-9]{2}[^0-9]))')
  audit(AUDIT_HOST_NOT, 'SRX1400/3400/3600/5400/5600/5800');

# Affected:
# Prior to 12.3X48-D45
# Prior to 15.1X49-D80
fixes = make_array();
fixes['12.3X48']     = '12.3X48-D45';
fixes['15.1X49']     = '15.1X49-D80';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern1 = "^set chassis fpc [^ ]+ pic [0-9]+ services-offload";
  pattern2 = "^set chassis fpc [0-9]+ np-cache";
  if (!junos_check_config(buf:buf, pattern:pattern1) ||
      !junos_check_config(buf:buf, pattern:pattern2))
    audit(AUDIT_HOST_NOT, "affected because 'services-offload' is not enabled");
  override = FALSE;
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
