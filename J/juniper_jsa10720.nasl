#TRUSTED 143bdf13051813a971ae8b534f71e181e4e835b11fdfc2e3187f7a5d2fe7d7e8f02cdd5829e82e6f3c596f82a1dc559c18717cf09e5939342866634fb76198698fcaac41cbf2a84257e258ff5eab23681c05f99cfd57c88eab6a08fad953bf12e58793f0d573d8d1def11e76671b03cf2ecedee78b0e4b329cae8d610e85d443309870ef51b97d36e50c5031d12b3c64c4186f187576e97bd52737e070255e4c53f8ae14383c209936a9981bf9b69f5bf90f6a237a7bdb569447efd28c09a631c927caa8174d9ca50be6a99152bd0b876a1d4457972a296ccfe967e7e667ea12d5f726385874009afa93f69d459ff11cf8ab876e6fce03b3c9b663d2e1ccc7eca31dcc7c69d6a77399c78034af2fb369cbb7c56a77b37aba603a90e72b8023c1335b231485a4af56f8d4ee8fbbad8c29678b32c5d7d05c0aaf3fd024f191f9b2e41b10ffed151891525ad03397c3c96051f80350ba9cd7f6875714790f0f32a3c4286d6f9a519d371d25bc31136109039712fab6bf99d40aed692ea409323ca83f7357cd012ae61081d2cbc50463da95ec775a34dcfb4321f34485d3afffea00767517c32bb2e583fed8ff72ab6140dde9145b6316091db30e707fc69b1d5e42f9d8d2a9d9747867d1e62fab8c3d1a2b2a8775371b94fefca01c7b8639c8dee99e8392a761d5ad59640b8172c245ec0fe4637687f3642b2a1365503fcdb7b8c3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88095);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1258");
  script_xref(name:"JSA", value:"JSA10720");

  script_name(english:"Juniper Junos HTTP Request Handling J-Web DoS (JSA10720)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by denial of service vulnerability due to a
flaw in the Embedthis Appweb Server when processing malformed HTTP
requests. An unauthenticated, remote attacker can exploit this to
crash the J-Web service.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10720");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10720.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D60';
fixes['12.1X46'] = '12.1X46-D45';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'   ] = '12.3R10'; # or 12.3R11
fixes['12.3X48'] = '12.3X48-D20';
fixes['13.2X51'] = '13.2X51-D20';
fixes['13.3'   ] = '13.3R8';
fixes['14.1'   ] = '14.1R6';
fixes['14.2'   ] = '14.2R5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if (fix == "12.3R10")
  fix += " or 12.3R11";

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
