#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2019.
#
include("compat.inc");

if (description)
{
  script_id(130007);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2019-3010");
  script_xref(name:"IAVA", value:"2019-A-0381-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Oracle Solaris Critical Patch Update : oct2019_SRU11_4_12_5_0");
  script_summary(english:"Check for the oct2019 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
oct2019."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: XScreenSaver). The supported version
    that is affected is 11. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. While the vulnerability is in
    Oracle Solaris, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in takeover of Oracle Solaris.
    (CVE-2019-3010)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2592433.1"
  );
  # https://www.oracle.com/ocom/groups/public/@otn/documents/webcontent/5760131.xml
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?c208ac13"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpuoct2019.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the oct2019 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3010");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Solaris xscreensaver log Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/17");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "11.4-11.4.12.0.1.5.0";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.12.0.1.5.0", sru:"11.4.12.5.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
