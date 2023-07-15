#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158023);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/10/11");

  script_cve_id("CVE-2021-25217");
  script_xref(name:"IAVB", value:"2021-B-0032-S");

  script_name(english:"EulerOS Virtualization 3.0.6.0 : dhcp (EulerOS-SA-2022-1063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dhcp packages installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - In ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16, ISC DHCP 4.4.0 -> 4.4.2 (Other branches of ISC DHCP (i.e., releases
    in the 4.0.x series or lower and releases in the 4.3.x series) are beyond their End-of-Life (EOL) and no
    longer supported by ISC. From inspection it is clear that the defect is also present in releases from
    those series, but they have not been officially tested for the vulnerability), The outcome of encountering
    the defect while reading a lease that will trigger it varies, according to: the component being affected
    (i.e., dhclient or dhcpd) whether the package was built as a 32-bit or 64-bit binary whether the compiler
    flag -fstack-protection-strong was used when compiling In dhclient, ISC has not successfully reproduced
    the error on a 64-bit system. However, on a 32-bit system it is possible to cause dhclient to crash when
    reading an improper lease, which could cause network connectivity problems for an affected system due to
    the absence of a running DHCP client process. In dhcpd, when run in DHCPv4 or DHCPv6 mode: if the dhcpd
    server binary was built for a 32-bit architecture AND the -fstack-protection-strong flag was specified to
    the compiler, dhcpd may exit while parsing a lease file containing an objectionable lease, resulting in
    lack of service to clients. Additionally, the offending lease and the lease immediately following it in
    the lease database may be improperly deleted. if the dhcpd server binary was built for a 64-bit
    architecture OR if the -fstack-protection-strong compiler flag was NOT specified, the crash will not
    occur, but it is possible for the offending lease and the lease which immediately followed it to be
    improperly deleted. (CVE-2021-25217)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1063
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6e4eeccf");
  script_set_attribute(attribute:"solution", value:
"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-relay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "dhcp-client-4.3.6-28.h17.eulerosv2r8",
  "dhcp-common-4.3.6-28.h17.eulerosv2r8",
  "dhcp-libs-4.3.6-28.h17.eulerosv2r8",
  "dhcp-relay-4.3.6-28.h17.eulerosv2r8",
  "dhcp-server-4.3.6-28.h17.eulerosv2r8"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
