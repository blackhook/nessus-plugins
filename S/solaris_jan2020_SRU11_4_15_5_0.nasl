#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2020.
#
include("compat.inc");

if (description)
{
  script_id(132996);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2019-9579", "CVE-2020-2647");
  script_xref(name:"IAVA", value:"2020-A-0018-S");

  script_name(english:"Oracle Solaris Critical Patch Update : jan2020_SRU11_4_15_5_0");
  script_summary(english:"Check for the jan2020 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jan2020."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: SMB Server). The supported version
    that is affected is 11. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. Successful attacks of this
    vulnerability can result in unauthorized update, insert
    or delete access to some of Oracle Solaris accessible
    data. (CVE-2019-9579)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Kernel). Supported versions that are
    affected are 10 and 11. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. Successful attacks require
    human interaction from a person other than the attacker.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of Oracle Solaris.
    (CVE-2020-2647)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2623333.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/a/tech/docs/cpujan2020cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujan2020.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jan2020 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-2647");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/01/16");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "11.4-11.4.15.0.1.5.0";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.15.0.1.5.0", sru:"11.4.15.5.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:solaris_get_report2());
  else security_note(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
