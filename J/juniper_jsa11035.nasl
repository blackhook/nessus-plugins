#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(139032);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1648");
  script_xref(name:"JSA", value:"JSA11035");

  script_name(english:"Junos OS: RPD crash when processing a specific BGP packet (JSA11035)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Junos OS installed on the remote host is affected by a denial of service (DoS) vulnerability. Processing
a specific BGP packet can lead to a routing process daemon (RPD) crash and restart. This issue can occur even before the
BGP session with the peer is established. Repeated receipt of this specific BGP packet can result in an extended DoS
condition.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11035");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11035");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1648");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/28");

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

# 18.2X75 versions starting from 18.2X75-D50.8, 18.2X75-D60 and later versions, prior to 18.2X75-D52.8, 18.2X75-D53,
# 18.2X75-D60.2, 18.2X75-D65.1, 18.2X75-D70;
if (ver =~ "^18\.2X75-D50")
{
  parts = split(ver, sep:'D', keep:FALSE);
  dpart = parts[1];
  if (ver_compare(ver:dpart, minver:'50.8', fix:'52.8', strict:FALSE) < 0)
    fixes['18.2X75'] = '18.2X75-D52.8';
}
if (ver =~ "^18\.2X75-D60")
{
  parts = split(ver, sep:'D', keep:FALSE);
  dpart = parts[1];
  if (ver_compare(ver:dpart, minver:'60', fix:'60.2', strict:FALSE) < 0)
    fixes['18.2X75'] = '18.2X75-D60.2';
}

if (ver =~ "^19\.4$")
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);
fixes['19.4'] = '19.4R1-S2';
fixes['20.1'] = '20.1R1-S2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_WARNING, port:0, extra:report);
