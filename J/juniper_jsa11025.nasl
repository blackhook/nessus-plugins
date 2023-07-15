#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138909);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2019-1551");
  script_xref(name:"JSA", value:"JSA11025");

  script_name(english:"Juniper Junos OpenSSL Security Advisory (JSA11025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Juniper Junos device is affected by a vulnerability in the OpenSSL
library. There is an overflow bug in the x64_64 Montgomery squaring procedure used in exponentiation with 512-bit
moduli. No EC algorithms are affected. Analysis suggests that attacks against 2-prime RSA1024, 3-prime RSA1536, and
DSA1024 as a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH512
are considered just feasible. However, for an attack the target would have to re-use the DH512 private key, which is not
recommended anyway. Also applications directly using the low level API BN_mod_exp may be affected if they use
BN_FLG_CONSTTIME.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/openssl-1.0.2-notes.html");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11025");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11025");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1551");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/12/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include('junos.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['15.1'] = '15.1R7-S7';
fixes['15.1X49'] = '15.1X49-D230';
fixes['15.1X53'] = '15.1X53-D593';
fixes['16.1'] = '16.1R7-S8';
fixes['17.2'] = '17.2R3-S4';
fixes['17.3'] = '17.3R3-S8';

if (ver =~ "^17\.4R3")
  fixes['17.4'] = '17.4R3-S1';
else
  fixes['17.4'] = '17.4R2-S10';

fixes['18.1'] = '18.1R3-S10';

if (ver =~ "^18\.2R3")
  fixes['18.2'] = '18.2R3-S4';
else
  fixes['18.2'] = '18.2R2-S7';

fixes['18.2X75'] = '18.2X75-D60';

if (ver =~ "^18\.3R3")
  fixes['18.3'] = '18.3R3-S2';
else if (ver =~ "^18\.3R2")
  fixes['18.3'] = '18.3R2-S4';
else
  fixes['18.3'] = '18.3R1-S7';

if (ver =~ "^18\.4R3")
  fixes['18.4'] = '18.4R3-S1';
else
  fixes['18.4'] = '18.4R2-S4';

if (ver =~ "^19\.1R2")
  fixes['19.1'] = '19.1R2-S1';
else
  fixes['19.1'] = '19.1R1-S5';

fixes['19.2'] = '19.2R1-S4';
fixes['19.3'] = '19.3R2-S2';
fixes['19.4'] = '19.4R1-S1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
