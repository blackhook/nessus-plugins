#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(130264);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/28");

  script_cve_id("CVE-2019-0057");
  script_xref(name:"JSA", value:"JSA10955");

  script_name(english:"NFX Series: Authentication Bypass Vulnerability Juniper Device Manager (JDM) (JSA10955)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"An authentication bypass vulnerability exists in Junos Device 
Manager. An authenticated, local attacker can exploit this to 
bypass regular security controls and take control of the system.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10955");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10955.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0057");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/25");

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
include('misc_func.inc');

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if ( 'NFX' >!< model)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver);

fixes = make_array();
fixes['18.2'] = '18.2R1';
fixes['18.2X75'] = '18.2X75-D5';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);
report = get_report(ver:ver, fix:fix);
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
