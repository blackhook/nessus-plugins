#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and patch checks in this plugin were 
# extracted from HP patch PHNE_43706. The text itself is
# copyright (C) Hewlett-Packard Development Company, L.P.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(72957);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2013-6209");
  script_bugtraq_id(66124);
  script_xref(name:"HP", value:"emr_na-c04174142");

  script_name(english:"HP-UX PHNE_43706 : s700_800 11.23 Lock Manager cumulative patch");
  script_summary(english:"Checks for the patch in the swlist output");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote HP-UX host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"s700_800 11.23 Lock Manager cumulative patch : 

A potential security vulnerability has been identified with HP-UX
running NFS rpc.lockd. The vulnerability could be exploited remotely
to create a Denial of Service (DoS)."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c04174142
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1d74a2dc"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Install patch PHNE_43706 or subsequent."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:hp:hp-ux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2021 Tenable Network Security, Inc.");
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

if (!hpux_check_ctx(ctx:"11.23"))
{
  exit(0, "The host is not affected since PHNE_43706 applies to a different OS release.");
}

patches = make_list("PHNE_43706");
foreach patch (patches)
{
  if (hpux_installed(app:patch))
  {
    exit(0, "The host is not affected because patch "+patch+" is installed.");
  }
}


flag = 0;
if (hpux_check_patch(app:"NFS.NFS-ENG-A-MAN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS-KRN", version:"B.11.23")) flag++;
if (hpux_check_patch(app:"NFS.NFS2-CORE", version:"B.11.23")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:hpux_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
