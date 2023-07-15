#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle CPU for oct2020.
#
include("compat.inc");

if (description)
{
  script_id(141772);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-14871");
  script_xref(name:"IAVA", value:"2020-A-0485-S");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0133");
  script_xref(name:"CEA-ID", value:"CEA-2020-0128");

  script_name(english:"Oracle Solaris Critical Patch Update : oct2020_SRU11_3_36_23_0");
  script_summary(english:"Check for the oct2020 CPU");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Solaris system is missing a security patch from CPU
oct2020."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This Solaris system is missing necessary patches to address a critical
security update :

  - Vulnerability in the Oracle Solaris product of Oracle
    Systems (component: Pluggable authentication module).
    Supported versions that are affected are 10 and 11.
    Easily exploitable vulnerability allows unauthenticated
    attacker with network access via multiple protocols to
    compromise Oracle Solaris. While the vulnerability is in
    Oracle Solaris, attacks may significantly impact
    additional products. Successful attacks of this
    vulnerability can result in takeover of Oracle Solaris.
    CVSS 3.1 Base Score 10.0 (Confidentiality, Integrity and
    Availability impacts). CVSS Vector:
    (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H).
    (CVE-2020-14871)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://support.oracle.com/epmos/faces/DocumentDisplay?id=2711819.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/a/tech/docs/cpuoct2020cvrf.xml"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.oracle.com/security-alerts/cpuoct2020.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Install the oct2020 CPU from the Oracle support website."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Oracle Solaris SunSSH PAM parse_user_name() Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/21");
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


fix_release = "0.5.11-0.175.3.36.0.23.0";

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.3.36.0.23.0", sru:"11.3.36.23.0") > 0) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:solaris_get_report2());
  else security_hole(0);
  exit(0);
}
audit(AUDIT_OS_RELEASE_NOT, "Solaris", fix_release, release);
