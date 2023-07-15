#TRUSTED 323c07a854fd61dc342da78333c220b70a7ac4062e3e3d9d18ea65f871a0ad2eede8b523f69aaa6af1a953cc81dce4312dfd0171b333cf462afad98be83244ec786d844c3c5529239a76be8b6b333c4a3443a4733a99b1da84f412f73ebb67d56a861e155552f9c81af54ad31e8288394f9b43eec546655694c9f656589c686d23846432f3d7a811ba97dee52e32f46d7b0b52029ace4877672087addfefef9e2ef14ce60111968a631db083b0012c97448b9ce7c4964b8984a2966b3bc90c8e5cae68d78866b35374284bff6276541928b09cb05f4115fb10c24a5a093d5a38de54b041b53dc6186c2190df55231bc052631c5e4eb92340e099a7bb785d3821a97c3d1f47bae3dade62e9fd5cb17044c639eb19135ce7d61d609c6e6ebb3a90ba0b55b1fe0c4c36bdd84b07103c86df0ffe781f61288072b6c1f252933a83eb98df4fbe011dcd8ee25afc3963c86d1eb688af263bcadbe649c7b99111daed9bf6e15cb9b4f972470df9499d01aba1d09e4f1785b808cf1384cd6fad560b7b46fcba3c08da5554853c559a317105d3518d874507e13dd878190b1a4a542591822bd82000c85ade30868845de2faa532866f920472fea7f5c7dcc73ad50411bf62dc1ec5c910965036c0d9e6c80e09a214cfeb07158ce813c30b1d15f9247528ecb8fd561aba56bdbbf1d83a55ba261e907505305fa0ee6dc0cabd35f03c4bc72
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');

include('compat.inc');

if (description)
{
  script_id(149366);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/11");

  script_cve_id("CVE-2021-0257");
  script_xref(name:"JSA", value:"JSA11148");

  script_name(english:"Juniper Junos DoS (JSA11148)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service vulnerability as referenced in 
the JSA11148 advisory. On Juniper Networks MX Series and EX9200 Series platforms with Trio-based MPCs (Modular Port
Concentrators) where Integrated Routing and Bridging (IRB) interfaces are configured and mapped to a VPLS instance or
a Bridge-Domain, certain Layer 2 network events at Customer Edge (CE) devices may cause memory leaks in the MPC of
Provider Edge (PE) devices which can cause an out of memory condition and MPC restart. When this issue occurs, there will
be temporary traffic interruption until the MPC is restored.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11148");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11148");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-0257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

var model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ "^(EX92|MX)")
{
  audit(AUDIT_DEVICE_NOT_VULN, model);
}

var ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');

var vuln_ranges = [
  {'min_ver':'17.3R3-S8', 'fixed_ver':'17.3R3-S10'},
  {'min_ver':'17.4R3-S2', 'fixed_ver':'17.4R3-S3'},
  {'min_ver':'18.2R3-S4', 'fixed_ver':'18.2R3-S7'},
  {'min_ver':'18.3R3-S2', 'fixed_ver':'18.3R3-S4'},
  {'min_ver':'18.4R3-S1', 'fixed_ver':'18.4R3-S6'},
  {'min_ver':'19.2R2', 'fixed_ver':'19.2R3-S2'},
  {'min_ver':'19.3R3', 'fixed_ver':'19.3R3-S1'},
  {'min_ver':'19.4R2', 'fixed_ver':'19.4R2-S2', 'fixed_display':'19.4R2-S2, 19.4R3'},
  {'min_ver':'20.2', 'fixed_ver':'20.2R1-S3', 'fixed_display':'20.2R1-S3, 20.2R2'},
  {'min_ver':'20.3', 'fixed_ver':'20.3R1-S1', 'fixed_display':'20.3R1-S1,, 20.3R2'}
];

var fix = junos_compare_range(target_version:ver, vuln_ranges:vuln_ranges);
if (empty_or_null(fix)) audit(AUDIT_INST_VER_NOT_VULN, 'Junos OS', ver);

#set routing-instances vrf instance-type vpls
#set routing-instances vrf interface irb.100
var buf = junos_command_kb_item(cmd:'show configuration | display set');
if (buf)
{
  var override = FALSE;
  if (!junos_check_config(buf:buf, pattern:"^set routing-instances .* instance-type vpls.*") ||
      !junos_check_config(buf:buf, pattern:"^set routing-instances .* interface irb.*"))
    audit(AUDIT_OS_CONF_NOT_VULN, 'Junos OS');
}
junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_NOTE);

