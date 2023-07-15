#TRUSTED 7a734640c418194f554dff3cafeb29d137581abacb4e72fecf9fcbb6d2ebad39d93f2dd7d0e8acaf65fd699efb1fa58e5582c69ec33371ea1e6052a30d075974dfacead2bcacff18e3392d3251b00a59288d3ffca4f0e99f8f2cffde783b8d5f9f21b9aa8841267b1f74bde464d09130bfd72c29c05d2a34e51f95e02fd553fa9ff7556639a166318035f5deb5ec66ba586a386ea17c2deebbf3c7f702fcf37c9ea963e29c2af7d14c31e26b14df48ed63abb1b4d3e59a9d1aba574731042ad67246d5f64793e954e3159fdee34d7ff11b5bda5522a3a4a059accf4347ccbce2821912c011c8cba83180779e2c342a2bbffa991841a73efa54650b6a2cc814d72e32af805511699a1bbf8b5ae93ac555853d524b8f53e27d5691ea281300bfec308e90f31c21d3eec80c3180bdc2813be372ed85f10ad48f520ed2b0dd276bdb9cd12eece5afe0624c94275df20549b67931a1940e1d8734cad0f4dcf9474ad35705ba83091d6cfc8e2287209e98fa243ca2849cdf497382b1f4b472e926cf29e894e2bb511d937e3dc053350a474d31891094b9ce34f259e5f3602d99e01c3ff2db09838b1bc085218af197657b62c8f1559b8a3a986da28cb236861f099ce7b7263af318e3513b4eb71bf313fbf9f9a7ef529e55c30dfb14908e57d58e03adb68304e5c4f7f745f52cf3096542a1ed98ae3b6891ee96ef0141ad8bbedbecc8
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138908);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1649");
  script_xref(name:"JSA", value:"JSA11036");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos MX Series PFE Small Packet DoS (JSA11036)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Juniper Junos OS device is affected by a denial of service (DoS)
vulnerability. When a device running Juniper Networks Junos OS with MPC7, MPC8, or MPC9 line cards installed and the
system is configured for inline IP reassembly, used by L2TP, MAP-E, GRE, and IPIP, the packet forwarding engine (PFE)
will become disabled upon receipt of small fragments requiring reassembly. By continuously sending fragmented packets
that cannot be reassembled, an attacker can repeatedly disable the PFE causing a sustained DoS.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11036");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11036");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1649");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
if (model !~ '^MX')
  audit(AUDIT_HOST_NOT, 'an affected model');

if (report_paranoia < 2)
  audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['17.2'] = '17.2R3-S4';
fixes['17.3'] = '17.3R3-S8';

if (ver =~ "^17\.4R3")
  fixes['17.4'] = '17.4R3-S1';
else
  fixes['17.4'] = '17.4R2-S9';

fixes['18.1'] = '18.1R3-S10';

if (ver =~ "^18\.2R3")
  fixes['18.2'] = '18.2R3-S3';
else
  fixes['18.2'] = '18.2R2-S6';

fixes['18.2X75'] = '18.2X75-D34';

if (ver =~ "^18\.3R3")
  fixes['18.3'] = '18.3R3-S2';
else if (ver =~ "^18\.3R2")
  fixes['18.3'] = '18.3R2-S4';
else
  fixes['18.3'] = '18.3R1-S7';

if (ver =~ "^18\.4R1")
  fixes['18.4'] = '18.4R1-S6';
else
  fixes['18.4'] = '18.4R2-S4';


if (ver =~ "^19\.1R1")
  fixes['19.1'] = '19.1R1-S4';
else
  fixes['19.1'] = '19.1R2-S1';

fixes['19.2'] = '19.2R1-S3';
fixes['19.3'] = '19.3R2-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
