#TRUSTED 33a6ff08689127243fb4ebbb932ed3c6c767e4c23e728fad11ba6c104641d71a72740ff0899a0511bf9128875428e691d708eefed06d52cb828f71bb349dddf8b9442cfb7ba7346d86ec2ca4d6b7a4c756156cd558d8ef6c30980c148fe3f18ccb8a1c4afe8898340b5223e05fb441e9f575b6381c838f9e73ab085a97c7b8f1ddce51a68ba5e770bab0ab0566846b814aa4eaa1a1868f85d3adefbbe39e65ade841862119f2eb59d80544cba57449b080366efb647b33bd7f933f07500892506c694c7aec70006795723b02d38415c92b75cfbc3dfbc611362525aed3a058eec77135001fd81e213611014c54a9ff3fe90e0c0bf1aaa35f7a0210eb2b915df5385f11aa6686500653b803502e3949298c07511650cd47d8e2614a95669ab7e55dab5c261788f2a58af34f7036df2af2fefbc441e600474ba5d7dbd838a370a1ab667b0459132f5a4ed4c761c9104f2ef291129d4a577b82dadab830c001bc3b4744a136017e8dae76425ba33447ae836dea90b4046e226727d156d4f3f92dcd7438c877e2aff8169b2f7ec34a0094637a1da71bf17fdf7eb0359f0e731480591bfa442bf0e897e2970ab8902f56daef7edaaacbda7c2c2e935076261c61d1fd3ed85fba3a3327b800d4a346156b60c0cc3e399585c360455153e6ea647c2c33ce2836657ea5929a272a79e334bedcd633a42287292f3d0f6baba58954f2b3a1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(133050);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/20");

  script_cve_id("CVE-2020-1606");
  script_xref(name:"JSA", value:"JSA10985");
  script_xref(name:"IAVA", value:"2020-A-0083");

  script_name(english:"Junos OS: Path traversal vulnerability in J-Web (JSA10985)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, a path traversal vulnerability in the Juniper Networks
Junos OS device may allow an authenticated J-web user to read files with 'world' readable permission and
delete files with 'world' writeable permission.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10985");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA10985.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1606");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/17");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('audit.inc');
include('junos.inc');
include('junos_kb_cmd_func.inc');
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

#15.1X49 versions prior to 15.1X49-D180 on SRX Series;
#12.3X48 versions prior to 12.3X48-D85 on SRX Series;

if (model =~ '^SRX')
  fixes['12.3X48'] = '12.3X48-D85';
  fixes['15.1X49'] = '15.1X49-D180';

#15.1X53 versions prior to 15.1X53-D238 on QFX5200/QFX5110 Series;

if (model =~ '^QFX5200' || model =~ '^QFX5110' )
  fixes['15.1X53'] = '15.1X53-D238';

#16.1 versions prior to 16.1R4-S13, 16.1R7-S5;
#17.2 versions prior to 17.2R1-S9, 17.2R3-S2;
#17.3 versions prior to 17.3R2-S5, 17.3R3-S5;
#17.4 versions prior to 17.4R2-S9, 17.4R3;
#18.3 versions prior to 18.3R2-S3, 18.3R3;
#18.3 versions prior to 18.3R2-S3, 18.3R3;

if (ver =~ "^16\.1R4")
  fixes['16.1'] = '16.1R4-S13';
else
  fixes['16.1'] = '16.1R7-S5';

if (ver =~ "^17\.2R1")
  fixes['17.2'] = '17.2R1-S9';
else
  fixes['17.2'] = '17.2R3-S2';

if (ver =~ "^17\.3R2")
  fixes['17.3'] = '17.3R2-S5';
else
  fixes['17.3'] = '17.3R3-S5';

if (ver =~ "^17\.4R2")
  fixes['17.4'] = '17.4R2-S9';
else
  fixes['17.4'] = '17.4R3';

if (ver =~ "^18\.3R2")
  fixes['18.3'] = '18.3R2-S3';
else
  fixes['18.3'] = '18.3R3';

if (ver =~ "^19\.1R1")
  fixes['19.1'] = '19.1R1-S4';
else
  fixes['19.1'] = '19.1R2';

fixes['12.3'] = '12.3R12-S13';
fixes['14.1X53'] = '14.1X53-D51';
fixes['15.1'] = '15.1R7-S5';
fixes['15.1F6'] = '15.1F6-S13';
fixes['16.2'] = '16.2R2-S10';
fixes['17.1'] = '17.1R3-S1';
fixes['18.1'] = '18.1R3-S8';
fixes['18.2'] = '18.2R3';
fixes['18.4'] = '18.4R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;

buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  override = FALSE;
  pattern = "^set system services web-management http(s)?";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable as J-Web is not enabled');
}

junos_report(model:model, ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);