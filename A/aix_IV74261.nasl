#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text in the description was extracted from AIX Security
# Advisory ntp_advisory3.asc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(85604);
  script_version("2.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/21");

  script_cve_id("CVE-2015-1799");
  script_bugtraq_id(73950);

  script_name(english:"AIX 7.1 TL 3 : ntp (IV74261)");
  script_summary(english:"Check for APAR IV74261.");

  script_set_attribute(attribute:"synopsis", value:
"The remote AIX host is missing a security patch.");
  script_set_attribute(attribute:"description", value:
"The remote AIX host has a version of Network Time Protocol (NTP)
installed that is affected by a denial of service vulnerability due to
a flaw in the symmetric-key feature in the receive() function in file
ntp_proto.c when receiving certain invalid packets, which causes
state-variable updates to be performed. A man-in-the-middle attacker
can exploit this, by spoofing the source IP of a peer, to cause a
synchronization loss.");
  script_set_attribute(attribute:"see_also", value:"https://aix.software.ibm.com/aix/efixes/security/ntp_advisory3.asc");
  script_set_attribute(attribute:"solution", value:
"Install the appropriate interim fix according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:ibm:aix:7.1");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"AIX Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");

  exit(0);
}

include("aix.inc");
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

if ( ! get_kb_item("Host/local_checks_enabled") ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
oslevel = get_kb_item_or_exit("Host/AIX/version");
if ( oslevel != "AIX-7.1" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 7.1", oslevel);
}

oslevelcomplete = chomp(get_kb_item("Host/AIX/oslevelsp"));
if (isnull(oslevelcomplete)) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
oslevelparts = split(oslevelcomplete, sep:'-', keep:0);
if ( max_index(oslevelparts) != 4 ) audit(AUDIT_UNKNOWN_APP_VER, "AIX");
ml = oslevelparts[1];
sp = oslevelparts[2];
if ( ml != "03" || sp != "05" )
{
  oslevel = ereg_replace(string:oslevel, pattern:"-", replace:" ");
  audit(AUDIT_OS_NOT, "AIX 7.1 ML 03 SP 05", oslevel + " ML " + ml + " SP " + sp);
}

if ( ! get_kb_item("Host/AIX/lslpp") ) audit(AUDIT_PACKAGE_LIST_MISSING);

if ( get_kb_item("Host/AIX/emgr_failure" ) ) exit( 0, "This AIX package check is disabled because : " + get_kb_item("Host/AIX/emgr_failure") );

flag = 0;

ifixes_7135 = "(IV74261s5a|IV83993m5a)";

if (aix_check_ifix(release:"7.1", ml:"03", sp:"05", patch:ifixes_7135, package:"bos.net.tcp.client", minfilesetver:"7.1.0.0", maxfilesetver:"7.1.3.45") < 0) flag++;

report_note = '\n' +
  'Note that iFix IV74261s5a is a mutually exclusive installation with' + '\n' +
  'iFix IV79943s5b. Neither are cumulative with each other, and both are' + '\n' +
  'required to resolve two different vulnerabilities at this package' + '\n' +
  'level. Apply cumulative iFix IV83993m5a to address both. Please contact' + '\n' +
  'IBM for further details.' + '\n';

if (flag)
{
  aix_report_extra = ereg_replace(string:aix_report_get(), pattern:"[()]", replace:"");
  aix_report_extra = ereg_replace(string:aix_report_extra, pattern:"[|]", replace:" or ");
  aix_report_extra += report_note;
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : aix_report_extra
  );
}
else
{
  tested = aix_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bos.net.tcp.client");
}
