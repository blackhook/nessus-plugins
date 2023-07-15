#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory perl_advisory5.asc.
#

include("compat.inc");

if (description)
{
  script_id(144314);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878", "CVE-2020-12723");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"AIX 7.1 TL 5 : perl (IJ26985)");
  script_summary(english:"Check for APAR IJ26985");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote AIX host is missing a security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10543
https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-10543 Perl
before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow
because nested regular expression quantifiers have an integer
overflow. Perl before 5.30.3 has an integer overflow related to
mishandling of a 'PL_regkind[OP(n)] == NOTHING' situation. A crafted
regular expression could lead to malformed bytecode with a possibility
of instruction injection. regcomp.c in Perl before 5.30.3 allows a
buffer overflow via a crafted regular expression because of recursive
S_study_chunk calls."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://aix.software.ibm.com/aix/efixes/security/perl_advisory5.asc"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the appropriate interim fix."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"AIX Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("aix.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if ( ! get_kb_item("Host/AIX/version") ) audit(AUDIT_OS_NOT, "AIX");
if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit(0, "This iFix check is disabled because : "+get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

if (aix_check_ifix(release:"7.1", ml:"05", sp:"05", patch:"IJ26985s1a", package:"7.1.5", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"05", patch:"IJ26985s1a", package:"7.1.5", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"IJ26985s1a", package:"7.1.5", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"06", patch:"IJ26985s1a", package:"7.1.5", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"IJ26985s1a", package:"7.1.5", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.1", ml:"05", sp:"07", patch:"IJ26985s1a", package:"7.1.5", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"00", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"00", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"01", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"01", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"02", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"02", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"03", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.20.1.0", maxfilesetver:"5.20.1.3") < 0) flag++;
if (aix_check_ifix(release:"7.2", ml:"04", sp:"03", patch:"IJ26985s1a", package:"7.2.4", minfilesetver:"5.28.1.0", maxfilesetver:"5.28.1.3") < 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:aix_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
