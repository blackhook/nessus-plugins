#TRUSTED acdf22da5df683fb976ca62a0b56a14e68cc952551773dd50fed80664109606feee77abd9c3540198cdf009917d492b54b92f9b70c12069883a978dcd5444a277c72e43745f90fca00c47a4a50ad04035295b2c694e49f46c7f68ab0343e802e369a42981606a1c124427f415af97202e003ea650031fd21ab69586c1b76ff2e80785bd93bb274b6c1667955adac1fdb724c2ebbbad4f7eae0b9bcc0853aec252e2633ad92568fba76f3dd377bee0e147499109daed69774cbfc5b94af3511aa8ac3bd592928e4d546b9c5cbcc842f529d69a58ab5ba4232dd9496681dde05f1e23222ee6b3af0d6db8f6ff3ccb5477ba8c6566fb96ba771025cadd923913dc9d084462ca57eaac8a9beb7107d166011333d8dd7e7eb0f707d29a34fffb998f625f8cdefceaf2956959396e0523bba02e498b3e6e564451b6accc5ff084fdf0c98746ea5cdbfcfa11936f1daa91932ed206ebb1ffeffd746808dfaa01226392c49fa620e8a9c25a33c1dd586404981742694d17e90ea41dcb755f34e254eadc959fd7b48ce20613ff6b8033da1f440e446d4ede1b5de2e68b500c7e86e1ddcf3a112d1912809ff3432de35523311ac4f00c1030a475609542f39189038aca1f28b94e668c9ee24f991325ba224c5135acceb8d53bf51360d0a771d0beebd05be1f709708350aa5ad2db065189b52221b5ccbb4d13d920affcf29699a5ddb879e
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138905);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/03");

  script_cve_id("CVE-2020-1653");
  script_xref(name:"JSA", value:"JSA11040");
  script_xref(name:"IAVA", value:"2020-A-0320-S");

  script_name(english:"Juniper Junos Kernel Crash (vmcore) or FPC Crash (JSA11040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Junos OS installed on the remote host is affected by a denial of service
(DoS) vulnerability. On Juniper Networks Junos OS devices, a stream of TCP packets sent to the Routing Engine (RE) may
cause mbuf leak which can lead to Flexible PIC Concentrator (FPC) crash or the system to crash and restart (vmcore).
This issue can be trigged by IPv4 or IPv6 and it is caused only by TCP packets. This issue is not related to any
specific configuration and it affects Junos OS releases starting from 17.4R1. However, this issue does not affect Junos
OS releases prior to 18.2R1 when Nonstop active routing (NSR) is configured [edit routing-options nonstop-routing].
The number of mbufs is platform dependent. Once the device runs out of mbufs, the FPC crashes or the vmcore occurs and
the device might become inaccessible requiring a manual restart. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported versio
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11040");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11040");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1653");

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
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');
include('junos_kb_cmd_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

if (ver =~ "^17\.4R3")
  fixes['17.4'] = '17.4R3-S2';
else
  fixes['17.4'] = '17.4R2-S11';

fixes['18.1'] = '18.1R3-S10';

if (ver =~ "^18\.2R3")
  fixes['18.2'] = '18.2R3-S5';
else
  fixes['18.2'] = '18.2R2-S7';

fixes['18.2X75'] = '18.2X75-D34';

if (ver =~ "^18\.3R3")
  fixes['18.3'] = '18.3R3-S2';
else
  fixes['18.3'] = '18.3R2-S4';

if (ver =~ "^18\.4R3")
  fixes['18.4'] = '18.4R3-S1';
else if (ver =~ "^18\.4R2")
  fixes['18.4'] = '18.4R2-S4';
else
  fixes['18.4'] = '18.4R1-S7';


if (ver =~ "^19\.1R2")
  fixes['19.1'] = '19.1R2-S1';
else
  fixes['19.1'] = '19.1R1-S5';

fixes['19.2'] = '19.2R1-S5';
fixes['19.3'] = '19.3R2-S3';
fixes['19.4'] = '19.4R1-S2';

# This issue does not affect Junos OS releases prior to 18.2R1 when Nonstop active routing (NSR) is configured
if (ver =~ "^17\.4" || ver =~ "^18\.1" || ver =~ "^18\.2($|R0)");
{
  buf = junos_command_kb_item(cmd:'show configuration | display set');
  if (buf)
  {
    pattern = "^set routing-options nonstop-routing";
    if (junos_check_config(buf:buf, pattern:pattern))
      audit(AUDIT_HOST_NOT, 'vulnerable as nonstop active routing is configured');
  }
}

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
