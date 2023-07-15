#TRUSTED 4b4bcf12c3201d7db8a3c5a1220644f4fab47eacc351a35e61ea04aed9fcd25c556d7a06eb69b76c9a17ad576012af7684a09129adfa4656874913d1c5dc0f4fbd0ee04a7e12173a0352ce4cd1bd0428f4174f30f25bb8128552ab50eebd76816bc4bbc3e4ebe0db6ce84d448ad401cb2f28fee5e6508cac5e78b6154c3bbceb852862e5645cda0cf50ccdb3611d9c0862381f1c1466e217e3ed775aa952ebff847ef432bf74d1fe64edbc70a8342d94c757dfe0b309acff3e0ec63a0b1b046d8dbc35706bd5bede3a2036b1ec81ba17884cce1b129624e45760c39d7c56e4db963ac3cf2916726b506f401e376c7df1d47443caa66b03cccee7fc3b4d4d8223ae0e80459a87d70d58683f51c8b6cd08f9a12d1888d4737d8baef3219461d1125cd99fcdb1ad2e78f669b7c0a0e65e8bc29605993cf84a9fc74c5bbec36aeeafb1dbf6dcab95ecec286d2fd80cf6ab6fe098f04750f6409c4c34f801bc18bfd8efda18e5dea3a2839071009ed9801046594fb6199ef9d3cba1c89b031e7d4af2223091dd72c4b0c9e3aeecc6f4880ed4f02a6b391b88fba53196ca99d889ff563dedbbc992a5c5a57b6f889ad1e1feec2519e02888daa06267ec91afe1265fc8e212abf7307579790ffac64175c0ed57f328ec887caa256b91e645ff12f2b4b3b99eab9059499de8122438cd5f301b9b0e12f515cd9c3930d1ca328ce721c29f
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(121642);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/09");

  script_cve_id("CVE-2019-0001");
  script_bugtraq_id(106541);
  script_xref(name:"JSA", value:"JSA10900");

  script_name(english:"Juniper Junos MX Malformed Packet - DOS (JSA10900)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"Receipt of a malformed packet on MX Series devices with dynamic 
  vlan configuration can trigger an uncontrolled recursion loop in 
  the Broadband Edge subscriber management daemon (bbe-smgd), 
  and lead to high CPU usage and a crash of the bbe-smgd service. 
  Repeated receipt of the same packet can result in an extended denial of service condition for the device.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10900");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in
Juniper advisory JSA10900.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0001");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/07");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include("junos_kb_cmd_func.inc");
include('misc_func.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
check_model(model:model, flags:MX_SERIES, exit_on_fail:TRUE);

fixes = make_array();
fixes['16.1'] = '16.1R7-S1';
fixes['16.2'] = '16.2R2-S7';
fixes['17.1'] = '17.1R2-S10';
fixes['17.2'] = '17.2R3';
fixes['17.3'] = '17.3R3-S1';
fixes['17.4'] = '17.4R2';
fixes['18.1'] = '18.1R3';
fixes['18.2'] = '18.2R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If  dynamic vlan isn't enabled in some form, audit out.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set dynamic-profile";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as it does not appear to have dynamic vlan enabled.');
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);

