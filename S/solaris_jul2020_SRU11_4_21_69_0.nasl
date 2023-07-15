#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jul2020.
#
include("compat.inc");

if (description)
{
  script_id(138539);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/08/11");

  script_cve_id("CVE-2018-12207", "CVE-2019-5489", "CVE-2020-14537", "CVE-2020-14542", "CVE-2020-14545", "CVE-2020-14724");
  script_xref(name:"IAVA", value:"2020-A-0325-S");
  script_xref(name:"IAVA", value:"2021-A-0190-S");

  script_name(english:"Oracle Solaris Critical Patch Update : jul2020_SRU11_4_21_69_0");
  script_summary(english:"Check for the jul2020 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jul2020."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Kernel). The supported version that
    is affected is 11. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. While the vulnerability is in
    Oracle Solaris, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in unauthorized ability to
    cause a hang or frequently repeatable crash (complete
    DOS) of Oracle Solaris. Note: Please refer to <a
    href='https://support.oracle.com/rs?type=doc&id=2609642.
    1'>My Oracle Support Note 2609642.1</a> for further
    information on how CVE-2018-12207 impacts Oracle
    Solaris. CVSS 3.1 Base Score 6.5 (Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H).
    (CVE-2018-12207)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Kernel). The supported version that
    is affected is 11. Difficult to exploit vulnerability
    allows low privileged attacker with network access via
    multiple protocols to compromise Oracle Solaris. While
    the vulnerability is in Oracle Solaris, attacks may
    significantly impact additional products. Successful
    attacks of this vulnerability can result in unauthorized
    read access to a subset of Oracle Solaris accessible
    data. CVSS 3.1 Base Score 3.5 (Confidentiality impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:L/I:N/A:N).
    (CVE-2019-5489)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Packaging Scripts). The supported
    version that is affected is 11. Easily exploitable
    vulnerability allows high privileged attacker with logon
    to the infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. Successful attacks require
    human interaction from a person other than the attacker
    and while the vulnerability is in Oracle Solaris,
    attacks may significantly impact additional products.
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a hang or frequently
    repeatable crash (complete DOS) of Oracle Solaris. CVSS
    3.1 Base Score 5.5 (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:H/UI:R/S:C/C:N/I:N/A:H).
    (CVE-2020-14537)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: libsuri). The supported version that
    is affected is 11. Easily exploitable vulnerability
    allows low privileged attacker with logon to the
    infrastructure where Oracle Solaris executes to
    compromise Oracle Solaris. Successful attacks of this
    vulnerability can result in unauthorized read access to
    a subset of Oracle Solaris accessible data. CVSS 3.1
    Base Score 3.3 (Confidentiality impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N).
    (CVE-2020-14542)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Device Driver Utility). The
    supported version that is affected is 11. Difficult to
    exploit vulnerability allows low privileged attacker
    with logon to the infrastructure where Oracle Solaris
    executes to compromise Oracle Solaris. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in unauthorized creation,
    deletion or modification access to critical data or all
    Oracle Solaris accessible data and unauthorized ability
    to cause a partial denial of service (partial DOS) of
    Oracle Solaris. CVSS 3.1 Base Score 5.0 (Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:N/I:H/A:L).
    (CVE-2020-14545)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Device Driver Utility). The
    supported version that is affected is 11. Easily
    exploitable vulnerability allows low privileged attacker
    with logon to the infrastructure where Oracle Solaris
    executes to compromise Oracle Solaris. Successful
    attacks require human interaction from a person other
    than the attacker. Successful attacks of this
    vulnerability can result in takeover of Oracle Solaris.
    CVSS 3.1 Base Score 7.3 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H).
    (CVE-2020-14724)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2684942.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/a/tech/docs/cpujul2020cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujul2020.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jul2020 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-14724");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/16");
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


fix_release = "11.4-11.4.21.0.1.69.0";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.21.0.1.69.0", sru:"11.4.21.0.1.69") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:solaris_get_report2());
  else security_warning(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
