#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2012.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(76829);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2012-0217", "CVE-2012-3204", "CVE-2012-3205", "CVE-2012-3209");
  script_bugtraq_id(53856, 56034, 56048, 56049);

  script_name(english:"Oracle Solaris Critical Patch Update : oct2012_SRU10_5");
  script_summary(english:"Check for the oct2012 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
oct2012."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Kernel). Supported
    versions that are affected are 10 and 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System takeover
    including arbitrary code execution. Note: CVE-2012-0217
    only affects Solaris instances running on platforms
    other than SPARC. (CVE-2012-0217)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Power Management). The
    supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized Operating System takeover
    including arbitrary code execution. (CVE-2012-3204)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Logical Domain(LDOM)).
    Supported versions that are affected are 10 and 11.
    Easily exploitable vulnerability requiring logon to
    Operating System. Successful attack of this
    vulnerability can result in unauthorized Operating
    System hang or frequently repeatable crash (complete
    DOS) as well as update, insert or delete access to some
    Solaris accessible data. Note: CVE-2012-3209 and
    CVE-2012-3215 only affects Solaris on the SPARC
    platform. (CVE-2012-3209)

  - Vulnerability in the Solaris component of Oracle Sun
    Products Suite (subcomponent: Vino server). The
    supported version that is affected is 11. Easily
    exploitable vulnerability requiring logon to Operating
    System. Successful attack of this vulnerability can
    result in unauthorized update, insert or delete access
    to some Solaris accessible data. (CVE-2012-3205)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=1475188.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/1865039.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?6c6537c6"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the oct2012 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'FreeBSD Intel SYSRET Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/07/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");


fix_release = "0.5.11-0.175.0.10.0.5.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.10.0.5.0", sru:"11/11 SRU 10.5") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
