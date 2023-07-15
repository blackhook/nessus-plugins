#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(138906);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/13");

  script_cve_id("CVE-2020-1651");
  script_xref(name:"JSA", value:"JSA11038");

  script_name(english:"Juniper Junos MX Series PFE DoS (JSA11038)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Juniper Junos device is affected by a denial of service (DoS)
vulnerability where receipt of a stream of specific Layer 2 frames may cause a memory leak resulting in the packet
forwarding engine (PFE) on the line card to crash and restart, causing traffic interruption. By continuously sending
this stream of specific layer 2 frame, an attacker connected to the same broadcast domain can repeatedly crash the PFE,
causing a prolonged Denial of Service (DoS). 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA11038");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper advisory JSA11038");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1651");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/24");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include('junos.inc');

model = get_kb_item_or_exit('Host/Juniper/model');
if ('MX' >!< model)
  audit(AUDIT_HOST_NOT, 'an affected model');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
fixes = make_array();

fixes['17.2'] = '17.2R3-S4';
fixes['17.2X75'] = '17.2X75-D105.19';
fixes['17.3'] = '17.3R3-S7';
fixes['17.4'] = '17.4R1-S3';
fixes['18.1'] = '18.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
