#TRUSTED 9ae406de498be8e12ba3e173f6cc891bb9a8fefb279a656222c8db047320c9f1479c89f61eeb518ee77b9dc6b27150e26e95d7c7e3af05efe8becf767b4cabe402080d45750bde67f4caa79f882961d71d0a28b3b9ad75c6df5602e18b2d0bde3198daf4e165ab33f430482c345910ca153f5c1deb0f7aa7c103b4611054b2c369c78e07c74d1d0c9e07d2133956cdb09763327e6a4bea49d7f6df825d85264e5f0155ea52bce45989f2fa9dcbf88bf11d8be224e5fa2d5d2a070abef4e2e3b06db04b48e75969a5cba720985dd574b943f50c913e3e1763f731b54a4cf745ab059db084dd19786389db9ed69839df8f8ed27fb11bb45e550b9a8a8140584c2c3d2a63fa16859010a25962a7d070323bed839aa559e7cce3af47232458acc8c7e2514682fd346959d81946445c09e6bd88bf85f63a3fb15a40b678afad6d42b948d33f62af160ab985d763fb455cf88fe3dc8028cf9e95649782ab5a04a3e30f737b57452431bdafbd0a18db6f0b49fdf23f23f03d63c3ce3b2c9a44ce763d81193a930e73a056a240d53921bf4fd3339aa1a78e2a8ae73291d73724c9e4a169aa09fd7892555d366eab2ec029af2beb111705cb0760a62871d83a68d1e6282c8516a1d41b8407834d0e7f7977137fb3f581ddaeed30d8ea9eb084b57daacd3a84a064f4f4861be7b2aae2b2565e13f1effaead1c5c713d89326c2d55592c770
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91762);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2019/01/02");

  script_cve_id("CVE-2016-1409");
  script_xref(name:"JSA", value:"JSA10749");

  script_name(english:"Juniper Junos IPv6 Neighbor Discovery (ND) Traffic Handling Multiple Vulnerabilities (JSA10749)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple vulnerabilities :

  - A flaw exists due to improper handling of malformed IPv6
    ND packets. An unauthenticated, remote attacker can
    exploit this, via specially crafted ND packets, to cause
    the device to stop processing IPv6 traffic, resulting in
    a denial of service condition.

  - A flaw exists that is triggered when handling QFX5100
    exceptions. An unauthenticated, remote attacker can
    exploit this to transition IPv6 ND traffic to the
    routing engine, resulting in a partial denial of service
    condition.

  - An unspecified flaw exists that allows an
    unauthenticated, remote attacker to cause improper
    forwarding of IPv6 ND traffic in violation of RFC4861.

Note that Nessus has not tested for these issues but has instead
relied only on the device's self-reported model and current
configuration.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10749");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10749.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2019 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/model", "Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include('global_settings.inc');
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
chip = NULL;
paranoid = FALSE;

check_model(
  model:model,
  flags:MX_SERIES | PTX_SERIES | QFX_SERIES | SRX_SERIES | EX_SERIES | M_SERIES,
  exit_on_fail:TRUE
);

fixes = make_array();

#MX_SERIES Different versions depending on chipset.
if(check_model(model:model, flags:MX_SERIES))
{
  buf = junos_command_kb_item(cmd:"show chassis hardware");
  if (buf)
  {
    # Trio/ichip based PFE modules part numbers
    #  https://kb.juniper.net/InfoCenter/index?page=content&id=KB25385
    part_numbers_trio = make_list(
      "750-028381",
      "750-031087",
      "750-028395",
      "750-031092",
      "750-038489",
      "750-038490",
      "750-031089",
      "750-028393",
      "750-028391",
      "750-031088",
      "750-028394",
      "750-031090",
      "750-024884",
      "750-038491",
      "750-038493",
      "750-038492",
      "750-028467",
      "711-031594",
      "711-031603",
      "711-038215",
      "711-038213",
      "711-038211",
      "711-038634"
    );
    part_numbers_ichip = make_list(
      "750-023594",
      "750-025469",
      "750-025470",
      "750-025471",
      "710-013699",
      "710-014219",
      "750-016670",
      "750-016833",
      "750-017679",
      "750-018122",
      "750-018124",
      "750-020220",
      "750-020221",
      "750-020452",
      "750-020456",
      "750-020503",
      "750-021157",
      "750-021566",
      "750-021567",
      "750-021617",
      "750-021679",
      "750-021680",
      "750-022366",
      "750-022765",
      "750-022766",
      "750-024064",
      "750-024199",
      "750-024387",
      "710-011663",
      "710-015795",
      "710-025843",
      "710-016168",
      "710-025853",
      "710-016170",
      "710-025855",
      "710-016172",
      "710-025464"
      );

    foreach part_number (part_numbers_trio)
    {
      if (part_number >< buf)
      {
        chip = "trio";
        break;
      }
    }
    foreach part_number (part_numbers_ichip)
    {
      if (part_number >< buf)
      {
        chip = "ichip";
        break;
      }
    }
  }
  else paranoid = TRUE;

  if(chip == "ichip")
  {
    fixes['16.1'] = '16.1R5';
    fixes['16.2'] = '16.2R2';
    fixes['17.1'] = '17.1R2';
    fixes['17.2'] = '17.2R1';
  }
  else if (chip == "trio")
  {
    fixes['13.3']   = '13.3R10';
    fixes['14.1R2'] = '14.1R2-S7';
    fixes['14.1R4'] = '14.1R4-S12';
    fixes['14.1']   = '14.1R8';
    fixes['14.2R7'] = '14.2R7-S1';
    fixes['14.2']   = '14.2R8';
    fixes['15.1F2'] = '15.1F2-S10';
    fixes['15.1F5'] = '15.1F5-S4';
    fixes['15.1F6'] = '15.1F6-S1';
    fixes['15.1F']  = '15.1F7';
    fixes['15.1R3'] = '15.1R3-S4';
    fixes['15.1R4'] = '15.1R4-S2';
    fixes['15.1R']  = '15.1R5';
    fixes['16.1R1'] = '16.1R1-S3';
    fixes['16.1']   = '16.1R2';
    fixes['16.2']   = '16.2R1';
    fixes['17.1']   = '17.1R1';
  }
  else
  {
    fixes['13.3']   = '13.3R10';
    fixes['14.1R2'] = '14.1R2-S7';
    fixes['14.1R4'] = '14.1R4-S12';
    fixes['14.1']   = '14.1R8';
    fixes['14.2R7'] = '14.2R7-S1';
    fixes['14.2']   = '14.2R8';
    fixes['15.1F2'] = '15.1F2-S10';
    fixes['15.1F5'] = '15.1F5-S4';
    fixes['15.1F6'] = '15.1F6-S1';
    fixes['15.1F']  = '15.1F7';
    fixes['15.1R3'] = '15.1R3-S4';
    fixes['15.1R4'] = '15.1R4-S2';
    fixes['15.1R']  = '15.1R5';
    fixes['16.1R1'] = '16.1R1-S3';
    fixes['16.1'] = '16.1R5';
    fixes['16.2'] = '16.2R2';
    fixes['17.1'] = '17.1R2';
    fixes['17.2'] = '17.2R1';
  }
}

#QFX10000
if (model =~ "^QFX10\d\d\d")
{
  fixes['15.1X53'] = '15.1X53-D60'; # or D105
  fixes['16.1']    = '16.1R2';
}

#QFX5100
if (model =~ "^QFX5100")
{
  fixes['14.1X53']  = '14.1X53-D43';
  fixes['15.1']     = '15.1R7'; 
  fixes['16.1']     = '16.1R5'; 
  fixes['17.1']     = '17.1R2';
  fixes['17.2']     = '17.2R1';
}

#SRX_SERIES
if(check_model(model:model, flags:SRX_SERIES))
{
  fixes['12.1X46'] = '12.1X46-D60';
  fixes['12.1X47'] = '12.1X47-D45';
  fixes['12.3X48'] = '12.3X48-D40';
  fixes['15.1X49'] = '15.1X49-D60';
}

#PTX_SERIES
if(check_model(model:model, flags:PTX_SERIES))
{
  fixes['15.1F5'] = '15.1F5-S4';
  fixes['15.1F6'] = '15.1F6-S2';
  fixes['16.1']   = '16.1R2'; # or 16.1R3
  fixes['16.2']   = '16.2R1'; 
  fixes['17.1']   = '17.1R1';
}

#EX_SERIES
if(check_model(model:model, flags:EX_SERIES))
{
  fixes['15.1'] = '15.1R6';
  fixes['16.1'] = '16.1R4';
}

#M_SERIES
if(check_model(model:model, flags:EX_SERIES))
{
  fixes['13.3']   = '13.3R10';
  fixes['14.1']   = '14.1R9';
  fixes['14.2']   = '14.2R8';
  fixes['15.1R5'] = '15.1R5-S1';
  fixes['15.1X53'] = '15.1X53-D63'; # or D70 / D210
}

override=TRUE;
# Check if IPv6 is enabled
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set interfaces .* family inet6 ";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because no interfaces have IPv6 enabled');
  override = FALSE;
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

if(check_model(model:model, flags:QFX_SERIES) && fix=='15.1X53-D60') fix += ' or 15.1X53-D105';
if(check_model(model:model, flags:PTX_SERIES) && fix=='16.1R2') fix += ' or 16.1R3';
if(check_model(model:model, flags:PTX_SERIES) && fix=='15.1X53-D63') fix += ' or 15.1X53-D70 or 15.1X53-D210';

if(paranoid && report_paranoia < 2) audit(AUDIT_POTENTIAL_VULN, "Juniper Junos", ver);
else junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING);
