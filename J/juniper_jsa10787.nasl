#TRUSTED 1b8845f649b71a5993ff8c625349cb442302ed686e8c474063d7f9f44a55796a3888b9cbb1b9089518d1366ba8af35f5242330466cbb9b8062cb92033dc53d412d7fea91983494d63873c514740676facfd6ea49b6ed4a344c3f1c7d16e1ff587b0d97c06bb08e0fd3e020d68a8a6e0cd68a8ccdbf86d627e1e5a6fb64a8404620ac52060f3574466b9ff91f2ff8114a910aad17f437e778e2aacafc9abc984c3de1cc2719a8ebb2f2b4bdd2e99a9a7cd19b2536aaf529e2a666d0c50488efcbedc82d57de51908ad506fad32c0f8569fe95592534ab9c08cdff557e70e49df0f381a2052cf33c28c7f64d3ea51e0fe7a1b967c7b2be30656a34a528f0dbd0d6fcfaca62f65e8cd2d94ad3fca4a32e1a162c574d44202e8d421001ad48e69f6beec177fd0d762e718785ef1009374c8a41c64c45cbc36c517c7463f695ec87d2e1718e0fbaa407c187f18ac519c431390aea0fd4552e8f4f10983c4800b7eaf71c2e22aa79d9723a5b3ea387902c12d7de703777e576bf4fe0306653cf01e30233410df53d23dfb6313af402e482cc0552ec8ab14db4438fb6e6444b7f1dafc88ca995fb8b891d4d998725ef6d1fd3cca1e43bd99275390e7fef7a220c23ab120768d30f7b839a1dd72fa433689ec41449cd771e1a77014fd33557a356449c6453fb01836d5ef8558f555f3cd5087f49dd2591d8bef7138281a3da29d32379a8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(102701);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2017-2341");
  script_xref(name:"JSA", value:"JSA10787");

  script_name(english:"Juniper Junos Virtualized Environment Guest-To-Host Privilege Escalation (JSA10787)");
  script_summary(english:"Checks the Junos version, model, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number and configuration, the
remote Juniper Junos device is affected by a privilege escalation
vulnerability when running in a virtualized environment due to
improper handling of authentication. An attacker on the Junos guest
can exploit this to escalate privileges and gain access to the host
operating system.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10787");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant Junos software release referenced in Juniper
security advisory JSA10787. Alternatively, as a workaround, enable
FIPS mode.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/08/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/model");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');

if (model !~ "^QFX(5110|5200|10002|10008|10016)" &&
    model !~ "^EX4600[1-4]" &&
    model !~ "^NFX250" &&
    model !~ "^SRX(1500|4100|4200)" &&
    model !~ "^ACX5\d\d\d" &&
    model !~ "^vSRX"
  )
  audit(AUDIT_HOST_NOT, 'an affected model.');

fixes = make_array();

fixes['14.1X53'] = '14.1X53-D40';
fixes['15.1X49'] = '15.1X49-D70';
fixes['15.1'] = '15.1R5';
fixes['16.1'] = '16.1R2';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# If FIPS is enabled it isn't vulnerable.
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  override = FALSE;
  pattern = "^set system fips level [1-4]";
  if (junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'vulnerable because it has FIPS mode enabled.');
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_HOLE);
