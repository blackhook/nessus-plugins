#TRUSTED aff0c1ee2e79c210ddd1c5779c73b64b87394450dc405097a247023d0c143557b16dbf4758ec74d956566470d1fb829f09e0009657209b109b744c91ba215b56dcd9d7377a84a3e1b77b7c6cd0feac7c4fca1dc92c786681231a54d539c79c870e29d06c9a4e8c176540b9ff80440b17c3e787851a0892f463356680d5af1b3894ed7ae2c0052367f18ed3687e8dde5814653822a66fa571b5f608cd87c4fed9c42c509af93e86e7190526c09e2c0f5592c81d67491a27686fc6a0510350ccde6e829352bf6ffbb0af8dad0f76bb9c1bd21e101cc05a057604569e9c86bdb01e4da69bb7f677f6f43087100caf00a1608d6d582d53e9bae5d24244df9b7bf68274a002f0613612092c920458f2b4169ba2aa50651d837d3d17f4b5a091a3cd1ffc4589e99501379a6d8e5ca62c2d69f33f1ecac34fc4293fa9ca93b3025d03bb608c45442eb03183cb99a1d0a460eecca6049a646666b10a22fdec169710425ee27e99857d36b492ae0b70ced394210ad0b110f8994d540c716798345dbeda004994a35124ed0bde72b01b27759afb0f10fcdbf87008c525295a760a0b7d9f77d43b9013682255aa74409ff271a7264646991ea13c594c0b4fdf49633753d8e1aad126ab7f09cbab7564e4dc86f36476287f2d98e416f0985ff3dd36e3a52455fc553af7e42a02f9fa1a1c41e08df2c26a74111dfd78b6f3e7114fbac5ba8806
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90761);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2018/08/10");

  script_cve_id("CVE-2016-1261");
  script_xref(name:"JSA", value:"JSA10723");

  script_name(english:"Juniper Junos J-Web Service Multiple Vulnerabilities (JSA10723)");
  script_summary(english:"Checks the Junos version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by multiple flaws in the J-Web service that
allow an unauthenticated, remote attacker to conduct a cross-site
request forgery (XSRF) attack or to cause a denial of service
condition.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/JSA10723");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release referenced in Juniper
advisory JSA10723.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2016-2018 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver   = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
model = get_kb_item_or_exit('Host/Juniper/model');
fixes = make_array();

fixes['12.1X44'] = '12.1X44-D55';
fixes['12.1X46'] = '12.1X46-D45';
fixes['12.1X47'] = '12.1X47-D30';
fixes['12.3'] = '12.3R11';
fixes['12.3X48'] = '12.3X48-D30';
fixes['13.2X51'] = '13.2X51-D40';
fixes['13.3'] = '13.3R8';
fixes['14.1'] = '14.1R6';
fixes['14.1X53'] = '14.1X53-D30';
fixes['14.2'] = '14.2R5';
fixes['15.1'] = '15.1R3';
fixes['15.1X49'] = '15.1X49-D20';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system services web-management";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because the web-management service is not enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, model:model, override:override, severity:SECURITY_WARNING, xsrf:TRUE);
