#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_16846. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(16985);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_xref(name:"HP", value:"HPSBUX9811-088");

  script_name(english:"HP-UX PHSS_16846 : s700_800 11.X OV EMANATE14.x Emanate Agent 14.2 patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.X OV EMANATE14.x Emanate Agent 14.2 patch : 

A SNMP community string in HP OpenView allow access to certain SNMP
variables."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_16846 or subsequent."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"1998/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/02/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"1998/11/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2021 Tenable Network Security, Inc.");
  script_family(english:"HP-UX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("hpux.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/HP-UX/version")) audit(AUDIT_OS_NOT, "HP-UX");
if (!get_kb_item("Host/HP-UX/swlist")) audit(AUDIT_PACKAGE_LIST_MISSING);

if (!hpux_check_ctx(ctx:"11.00"))
{
  exit(0, "The host is not affected since PHSS_16846 applies to a different OS release.");
}

patches = make_list("PHSS_16846", "PHSS_17387", "PHSS_17945", "PHSS_20544", "PHSS_21046", "PHSS_23670", "PHSS_24945", "PHSS_26138", "PHSS_27858", "PHSS_39886", "PHSS_41032", "PHSS_41556", "PHSS_42775", "PHSS_43156", "PHSS_43646", "PHSS_43817", "PHSS_44264");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.MASTER", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-HPUNIX", version:"B.11.01")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-MIB2", version:"B.11.00")) flag++;
if (hpux_check_patch(app:"OVSNMPAgent.SUBAGT-MIB2", version:"B.11.01")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
