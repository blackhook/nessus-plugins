#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104035);
  script_version("1.4");
  script_cvs_date("Date: 2018/07/12 19:01:16");

  script_cve_id("CVE-2017-10611");
  script_xref(name:"JSA", value:"JSA10814");

  script_name(english:"Juniper Junos FPC Crash Vulnerability (JSA10814)");
  script_summary(english:"Checks the Junos version and build date.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Junos device
is affected by a vulnerability in the extended-statistics component that 
can cause the FPC to crash.");
  # https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10814&actp=METADATA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fcab52ab");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workarounds referenced in
Juniper advisory JSA10814.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("junos_kb_cmd_func.inc");

# Since we're unable to check the config we're making this paranoid
if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ '^(MX[0-9]|MX-MPC[7-9]|EX22[0-9][0-9]|EX33[0-9][0-9]|XRE2[0-9])')
    audit(AUDIT_HOST_NOT, 'an affected model');

# Only lists the patches
fixes = make_array();
fixes['14.1']     = '14.1R8-S5';
fixes['14.1X53']  = '14.1X53-D46';
fixes['14.2']     = '14.2R7-S9';
fixes['15.1R1']   = '15.1R5-S3';
fixes['16.1R1']   = '16.1R4-S5';
fixes['16.1X65']  = '16.1X65-D45';
fixes['16.2']     = '16.2R2-S1';
fixes['17.1']     = '17.1R2-S2';
fixes['17.2']     = '17.2R1-S3';
fixes['17.2X75']  = '17.2X75-D50';
fixes['17.3']     = '17.3R1-S1';
fixes['17.4']     = '17.4R1';

if (ver =~ "^15\.1F[0-5]")  fixes['15.1F'] = '15.1F5-S8';
else if (ver =~ "^15\.1F6") fixes['15.1F'] = '15.1F6-S8';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = FALSE;

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_HOLE);
