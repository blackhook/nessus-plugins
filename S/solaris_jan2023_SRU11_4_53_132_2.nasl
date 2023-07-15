#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for jan2023.
#
include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(170171);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/04/20");

  script_cve_id("CVE-2021-46848", "CVE-2022-23218", "CVE-2022-23219", "CVE-2022-3204", "CVE-2022-3276", "CVE-2022-37797", "CVE-2022-39253", "CVE-2022-39260", "CVE-2022-3970", "CVE-2022-41556", "CVE-2022-43680", "CVE-2022-44638", "CVE-2022-45061", "CVE-2022-45063", "CVE-2022-46872", "CVE-2022-46874", "CVE-2022-46875", "CVE-2022-46878", "CVE-2022-46880", "CVE-2022-46881", "CVE-2022-46882", "CVE-2023-21900");
  script_xref(name:"IAVA", value:"2023-A-0046");

  script_name(english:"Oracle Solaris Critical Patch Update : jan2023_SRU11_4_53_132_2");
  script_summary(english:"Check for the jan2023 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
jan2023."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address critical
security updates :

  - Vulnerability in the Oracle Communications Session
    Border Controller product of Oracle Communications
    (component: Routing (glibc)). Supported versions that
    are affected are 8.4, 9.0 and 9.1. Difficult to exploit
    vulnerability allows unauthenticated attacker with
    network access via HTTP to compromise Oracle
    Communications Session Border Controller. Successful
    attacks of this vulnerability can result in unauthorized
    ability to cause a hang or frequently repeatable crash
    (complete DOS) of Oracle Communications Session Border
    Controller as well as unauthorized update, insert or
    delete access to some of Oracle Communications Session
    Border Controller accessible data and unauthorized read
    access to a subset of Oracle Communications Session
    Border Controller accessible data. CVSS 3.1 Base Score
    7.0 (Confidentiality, Integrity and Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:H).
    (CVE-2022-23219)

  - Vulnerability in the Oracle Communications Cloud Native
    Core Unified Data Repository product of Oracle
    Communications (component: Signaling (glibc)). The
    supported version that is affected is 22.1.1. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via HTTP to compromise
    Oracle Communications Cloud Native Core Unified Data
    Repository. Successful attacks of this vulnerability can
    result in takeover of Oracle Communications Cloud Native
    Core Unified Data Repository. CVSS 3.1 Base Score 9.8
    (Confidentiality, Integrity and Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H).
    (CVE-2022-23218)

  - Vulnerability in the Oracle Communications Cloud Native
    Core Policy product of Oracle Communications (component:
    Policy (GNU Libtasn1)). Supported versions that are
    affected are 22.4.0-22.4.4 and 23.1.0-23.1.1. Easily
    exploitable vulnerability allows unauthenticated
    attacker with network access via HTTPS to compromise
    Oracle Communications Cloud Native Core Policy.
    Successful attacks of this vulnerability can result in
    unauthorized access to critical data or complete access
    to all Oracle Communications Cloud Native Core Policy
    accessible data and unauthorized ability to cause a hang
    or frequently repeatable crash (complete DOS) of Oracle
    Communications Cloud Native Core Policy. CVSS 3.1 Base
    Score 9.1 (Confidentiality and Availability impacts).
    CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H).
    (CVE-2021-46848)

  - Vulnerability in the Oracle Outside In Technology
    product of Oracle Fusion Middleware (component:
    DC-Specific Component (LibExpat)). The supported version
    that is affected is 8.5.6. Easily exploitable
    vulnerability allows unauthenticated attacker with
    network access via HTTP to compromise Oracle Outside In
    Technology. Successful attacks of this vulnerability can
    result in unauthorized ability to cause a hang or
    frequently repeatable crash (complete DOS) of Oracle
    Outside In Technology. CVSS 3.1 Base Score 7.5
    (Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H).
    (CVE-2022-43680)

  - Vulnerability in the Oracle Database OML4PY (Python)
    component of Oracle Database Server. The supported
    version that is affected is 21c. Easily exploitable
    vulnerability allows low privileged attacker having
    Authenticated User privilege with network access via
    HTTP to compromise Oracle Database OML4PY (Python).
    Successful attacks of this vulnerability can result in
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Oracle Database OML4PY
    (Python). CVSS 3.1 Base Score 4.3 (Availability
    impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L).
    (CVE-2022-45061)

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: NSSwitch). Supported versions that
    are affected are 10 and 11. Difficult to exploit
    vulnerability allows high privileged attacker with
    network access via multiple protocols to compromise
    Oracle Solaris. Successful attacks require human
    interaction from a person other than the attacker and
    while the vulnerability is in Oracle Solaris, attacks
    may significantly impact additional products (scope
    change). Successful attacks of this vulnerability can
    result in unauthorized update, insert or delete access
    to some of Oracle Solaris accessible data and
    unauthorized ability to cause a partial denial of
    service (partial DOS) of Oracle Solaris. CVSS 3.1 Base
    Score 4.0 (Integrity and Availability impacts). CVSS
    Vector: (CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:C/C:N/I:L/A:L).
    (CVE-2023-21900)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2920776.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/docs/tech/security-alerts/cpujan2023cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpujan2023.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the jan2023 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-23219");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
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


fix_release = "11.4-11.4.53.0.1.132.2";

flag = 0;

if (solaris_check_release(release:"11.4-11.4.53.0.1.132.2", sru:"11.4.53.132.2") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
