#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHSS_30160. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(17519);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_bugtraq_id(8911);
  script_xref(name:"HP", value:"HPSBUX0401");
  script_xref(name:"HP", value:"SSRT4681");

  script_name(english:"HP-UX PHSS_30160 : HPSBUX0401-305 SSRT4681 Apache 1.3.29 web server on VVOS");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.04 Virtualvault 4.5 OWS update : 

Multiple stack-based buffer overflows in mod_alias and mod_rewrite
modules for Apache versions prior to 1.3.29."
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHSS_30160 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/18");
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

if (!hpux_check_ctx(ctx:"11.04"))
{
  exit(0, "The host is not affected since PHSS_30160 applies to a different OS release.");
}

patches = make_list("PHSS_30160", "PHSS_30648", "PHSS_31828", "PHSS_32184", "PHSS_33396", "PHSS_34119", "PHSS_35107", "PHSS_35461", "PHSS_35556");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"VaultTS.VV-CORE-CMN", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-GUI", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-JAVA", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultTS.VV-IWS-JK", version:"A.04.50")) flag++;
if (hpux_check_patch(app:"VaultWS.WS-CORE", version:"A.04.50")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:hpux_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
