#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0017. The text
# itself is copyright (C) ZTE, Inc.

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(127171);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id(
    "CVE-2008-0960",
    "CVE-2008-2292",
    "CVE-2008-4309",
    "CVE-2008-6123"
  );

  script_name(english:"NewStart CGSL MAIN 5.04 : net-snmp Multiple Vulnerabilities (NS-SA-2019-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 5.04, has net-snmp packages installed that are affected by multiple
vulnerabilities:

  - SNMPv3 HMAC verification in (1) Net-SNMP 5.2.x before
    5.2.4.1, 5.3.x before 5.3.2.1, and 5.4.x before 5.4.1.1;
    (2) UCD-SNMP; (3) eCos; (4) Juniper Session and Resource
    Control (SRC) C-series 1.0.0 through 2.0.0; (5) NetApp
    (aka Network Appliance) Data ONTAP 7.3RC1 and 7.3RC2;
    (6) SNMP Research before 16.2; (7) multiple Cisco IOS,
    CatOS, ACE, and Nexus products; (8) Ingate Firewall
    3.1.0 and later and SIParator 3.1.0 and later; (9) HP
    OpenView SNMP Emanate Master Agent 15.x; and possibly
    other products relies on the client to specify the HMAC
    length, which makes it easier for remote attackers to
    bypass SNMP authentication via a length value of 1,
    which only checks the first byte. (CVE-2008-0960)

  - Buffer overflow in the __snprint_value function in
    snmp_get in Net-SNMP 5.1.4, 5.2.4, and 5.4.1, as used in
    SNMP.xs for Perl, allows remote attackers to cause a
    denial of service (crash) and possibly execute arbitrary
    code via a large OCTETSTRING in an attribute value pair
    (AVP). (CVE-2008-2292)

  - Integer overflow in the netsnmp_create_subtree_cache
    function in agent/snmp_agent.c in net-snmp 5.4 before
    5.4.2.1, 5.3 before 5.3.2.3, and 5.2 before 5.2.5.1
    allows remote attackers to cause a denial of service
    (crash) via a crafted SNMP GETBULK request, which
    triggers a heap-based buffer overflow, related to the
    number of responses or repeats. (CVE-2008-4309)

  - The netsnmp_udp_fmtaddr function
    (snmplib/snmpUDPDomain.c) in net-snmp 5.0.9 through
    5.4.2.1, when using TCP wrappers for client
    authorization, does not properly parse hosts.allow
    rules, which allows remote attackers to bypass intended
    access restrictions and execute SNMP queries, related to
    source/destination IP address confusion.
    (CVE-2008-6123)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0017");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL net-snmp packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0960");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 119, 287);


  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 5.04")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 5.04');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 5.04": [
    "net-snmp-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-agent-libs-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-debuginfo-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-devel-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-gui-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-libs-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-perl-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-python-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-sysvinit-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3",
    "net-snmp-utils-5.7.2-28.el7_4.1.cgslv5.0.1.g4ee51b3"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");
}
