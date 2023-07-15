#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for apr2020.
#
include("compat.inc");

if (description)
{
  script_id(135667);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2020-2851", "CVE-2020-2927", "CVE-2020-2944");
  script_xref(name:"IAVA", value:"2020-A-0154-S");

  script_name(english:"Oracle Solaris Critical Patch Update : apr2020_SRU11_3_36_20_0");
  script_summary(english:"Check for the apr2020 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
apr2020."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Common Desktop Environment).
    Supported versions that are affected are 10 and 11.
    Difficult to exploit vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    Solaris executes to compromise Oracle Solaris. While the
    vulnerability is in Oracle Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    Oracle Solaris. (CVE-2020-2851)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Common Desktop Environment).
    Supported versions that are affected are 10 and 11.
    Difficult to exploit vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    Solaris executes to compromise Oracle Solaris. While the
    vulnerability is in Oracle Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    Oracle Solaris. (CVE-2020-2927)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Common Desktop Environment).
    Supported versions that are affected are 10 and 11.
    Easily exploitable vulnerability allows low privileged
    attacker with logon to the infrastructure where Oracle
    Solaris executes to compromise Oracle Solaris. While the
    vulnerability is in Oracle Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in takeover of
    Oracle Solaris. (CVE-2020-2944)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2650589.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpuapr2020.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the apr2020 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "0.5.11-0.175.3.36.0.20.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.36.0.20.0", sru:"11.3.36.20.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
