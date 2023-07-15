#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169829);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id(
    "CVE-2022-24805",
    "CVE-2022-24806",
    "CVE-2022-24807",
    "CVE-2022-24808",
    "CVE-2022-24809",
    "CVE-2022-24810"
  );
  script_xref(name:"IAVA", value:"2022-A-0305");

  script_name(english:"EulerOS Virtualization 2.9.0 : net-snmp (EulerOS-SA-2023-1228)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the net-snmp packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A flaw was found in net-snmp. A buffer overflow in the handling of the INDEX of NET-SNMP-VACM-MIB can
    cause an out-of-bounds memory access issue. (CVE-2022-24805)

  - A flaw was found in net-snmp. This issue occurs due to improper input validation when simultaneously
    setting malformed OIDs in the master agent and subagent. (CVE-2022-24806)

  - A flaw was found in net-snmp. A malformed OID in a SET request to the SNMP-VIEW-BASED-ACM-
    MIB::vacmAccessTable can cause an out-of-bounds memory access issue. (CVE-2022-24807)

  - A flaw was found in net-snmp. A malformed OID in a SET request to NET-SNMP-AGENT-MIB::nsLogTable can cause
    a NULL pointer dereference issue. (CVE-2022-24808)

  - A flaw was found in net-snmp. A malformed OID in a GET-NEXT to the nsVacmAccessTable can cause a NULL
    pointer dereference issue. (CVE-2022-24809)

  - A flaw was found in net-snmp. A malformed OID in a SET to the nsVacmAccessTable can cause a NULL pointer
    dereference issue. (CVE-2022-24810)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1228
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?aa508cea");
  script_set_attribute(attribute:"solution", value:
"Update the affected net-snmp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-24810");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.9.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "net-snmp-5.8-8.h7.eulerosv2r9",
  "net-snmp-libs-5.8-8.h7.eulerosv2r9",
  "python3-net-snmp-5.8-8.h7.eulerosv2r9"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "net-snmp");
}
