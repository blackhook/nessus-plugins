#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2021.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(154265);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2021-35539", "CVE-2021-35589");
  script_xref(name:"IAVA", value:"2021-A-0489-S");

  script_name(english:"Oracle Solaris Critical Patch Update : oct2021_SRU11_4_36_101_2");
  script_summary(english:"Check for the oct2021 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
oct2021."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Filesystem). The supported version
    that is affected is 11. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. While the vulnerability is in
    Oracle Solaris, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Oracle Solaris. CVSS 3.1 Base Score 6.5
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H).
    (CVE-2021-35539)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Device drivers). The supported
    version that is affected is 11. Easily exploitable
    vulnerability allows high privileged attacker with logon
    to the infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. While the vulnerability is in
    Oracle Solaris, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Oracle Solaris. CVSS 3.1 Base Score 6.0
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:N/S:C/C:N/I:N/A:H).
    (CVE-2021-35589)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2809232.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/a/tech/docs/cpuoct2021cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpuoct2021.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the oct2021 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-35589");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "11.4-11.4.36.0.1.101.2";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.36.0.1.101.2", sru:"11.4.36.101.2") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
