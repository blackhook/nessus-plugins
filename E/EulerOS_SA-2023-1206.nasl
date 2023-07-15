#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169870);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/11");

  script_cve_id("CVE-2022-3204", "CVE-2022-30698", "CVE-2022-30699");

  script_name(english:"EulerOS Virtualization 2.9.1 : unbound (EulerOS-SA-2023-1206)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the unbound packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - NLnet Labs Unbound, up to and including version 1.16.1 is vulnerable to a novel type of the 'ghost domain
    names' attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a
    subdomain of a rogue domain name. The rogue nameserver returns delegation information for the subdomain
    that updates Unbound's delegation cache. This action can be repeated before expiry of the delegation
    information by querying Unbound for a second level subdomain which the rogue nameserver provides new
    delegation information. Since Unbound is a child-centric resolver, the ever-updating child delegation
    information can keep a rogue domain name resolvable long after revocation. From version 1.16.2 on, Unbound
    checks the validity of parent delegation records before using cached delegation information.
    (CVE-2022-30698)

  - NLnet Labs Unbound, up to and including version 1.16.1, is vulnerable to a novel type of the 'ghost domain
    names' attack. The vulnerability works by targeting an Unbound instance. Unbound is queried for a rogue
    domain name when the cached delegation information is about to expire. The rogue nameserver delays the
    response so that the cached delegation information is expired. Upon receiving the delayed answer
    containing the delegation information, Unbound overwrites the now expired entries. This action can be
    repeated when the delegation information is about to expire making the rogue delegation information ever-
    updating. From version 1.16.2 on, Unbound stores the start time for a query and uses that to decide if the
    cached delegation information can be overwritten. (CVE-2022-30699)

  - A vulnerability named 'Non-Responsive Delegation Attack' (NRDelegation Attack) has been discovered in
    various DNS resolving software. The NRDelegation Attack works by having a malicious delegation with a
    considerable number of non responsive nameservers. The attack starts by querying a resolver for a record
    that relies on those unresponsive nameservers. The attack can cause a resolver to spend a lot of
    time/resources resolving records under a malicious delegation point where a considerable number of
    unresponsive NS records reside. It can trigger high CPU usage in some resolver implementations that
    continually look in the cache for resolved NS records in that delegation. This can lead to degraded
    performance and eventually denial of service in orchestrated attacks. Unbound does not suffer from high
    CPU usage, but resources are still needed for resolving the malicious delegation. Unbound will keep trying
    to resolve the record until hard limits are reached. Based on the nature of the attack and the replies,
    different limits could be reached. From version 1.16.3 on, Unbound introduces fixes for better performance
    when under load, by cutting opportunistic queries for nameserver discovery and DNSKEY prefetching and
    limiting the number of times a delegation point can issue a cache lookup for missing records.
    (CVE-2022-3204)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1206
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd1f084d");
  script_set_attribute(attribute:"solution", value:
"Update the affected unbound packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-30699");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/08/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "python3-unbound-1.7.3-18.h8.eulerosv2r9",
  "unbound-1.7.3-18.h8.eulerosv2r9",
  "unbound-libs-1.7.3-18.h8.eulerosv2r9"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unbound");
}
