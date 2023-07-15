#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(165858);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/09");

  script_cve_id(
    "CVE-2022-24805",
    "CVE-2022-24806",
    "CVE-2022-24807",
    "CVE-2022-24808",
    "CVE-2022-24809",
    "CVE-2022-24810"
  );
  script_xref(name:"IAVA", value:"2022-A-0305");

  script_name(english:"EulerOS 2.0 SP8 : net-snmp (EulerOS-SA-2022-2474)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the net-snmp packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - The vulnerability exists due to a boundary error when handling INDEX of NET-SNMP-VACM-MIB. A remote
    attacker can trick the victim into loading a specially crafted MIB collection, trigger an out-of-bounds
    write and execute arbitrary code on the target system. (CVE-2022-24805)

  - The vulnerability exists due to insufficient validation of user-supplied input when SETing malformed OIDs
    in master agent and subagent simultaneously. A remote user can pass specially crafted input to the
    application and perform a denial of service (DoS) attack. (CVE-2022-24806)

  - The vulnerability exists due to a boundary error in a SET request to SNMP-VIEW-BASED-ACM-
    MIB::vacmAccessTable. A remote user can pass a malformed OID in a SET request, trigger an out-of-bounds
    write and execute arbitrary code on the target system. (CVE-2022-24807)

  - The vulnerability exists due to a NULL pointer dereference error in NET-SNMP-AGENT-MIB::nsLogTable when
    handling malformed OID in a SET request. A remote user can pass specially crafted data to the application
    and perform a denial of service (DoS) attack. (CVE-2022-24808)

  - The vulnerability exists due to a NULL pointer dereference error in nsVacmAccessTable  when handling
    malformed OID in GET-NEXT. A remote user can pass specially crafted data to the application and perform a
    denial of service (DoS) attack. (CVE-2022-24809)

  - The vulnerability exists due to a NULL pointer dereference error in nsVacmAccessTable when handling
    malformed OID in a SET request. A remote user can pass specially crafted data to the application and
    perform a denial of service (DoS) attack. (CVE-2022-24810)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-2474
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?87a9b04f");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp-agent-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:net-snmp-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "net-snmp-5.8-1.h5.eulerosv2r8",
  "net-snmp-agent-libs-5.8-1.h5.eulerosv2r8",
  "net-snmp-devel-5.8-1.h5.eulerosv2r8",
  "net-snmp-libs-5.8-1.h5.eulerosv2r8",
  "net-snmp-utils-5.8-1.h5.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
