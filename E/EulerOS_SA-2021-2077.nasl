#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151348);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/08");

  script_cve_id(
    "CVE-2018-5732",
    "CVE-2021-25217"
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.2.0 : dhcp (EulerOS-SA-2021-2077)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dhcp packages installed, the EulerOS
Virtualization for ARM 64 installation on the remote host is affected
by the following vulnerabilities :

  - DHCP (Dynamic Host Configuration Protocol) is a
    protocol which allows individual devices on an IP
    network to get their own network configuration
    information (IP address, subnetmask, broadcast address,
    etc.) from a DHCP server. The overall purpose of DHCP
    is to make it easier to administer a large network. To
    use DHCP on your network, install a DHCP service (or
    relay agent), and on clients run a DHCP client daemon.
    The dhcp package provides the ISC DHCP service and
    relay agent. Security Fix(es):In ISC DHCP 4.1-ESV-R1 ->
    4.1-ESV-R16, ISC DHCP 4.4.0 -> 4.4.2 (Other branches of
    ISC DHCP (i.e., releases in the 4.0.x series or lower
    and releases in the 4.3.x series) are beyond their
    End-of-Life (EOL) and no longer supported by ISC. From
    inspection it is clear that the defect is also present
    in releases from those series, but they have not been
    officially tested for the vulnerability), The outcome
    of encountering the defect while reading a lease that
    will trigger it varies, according to: the component
    being affected (i.e., dhclient or dhcpd) whether the
    package was built as a 32-bit or 64-bit binary whether
    the compiler flag -fstack-protection-strong was used
    when compiling In dhclient, ISC has not successfully
    reproduced the error on a 64-bit system. However, on a
    32-bit system it is possible to cause dhclient to crash
    when reading an improper lease, which could cause
    network connectivity problems for an affected system
    due to the absence of a running DHCP client process. In
    dhcpd, when run in DHCPv4 or DHCPv6 mode: if the dhcpd
    server binary was built for a 32-bit architecture AND
    the -fstack-protection-strong flag was specified to the
    compiler, dhcpd may exit while parsing a lease file
    containing an objectionable lease, resulting in lack of
    service to clients. Additionally, the offending lease
    and the lease immediately following it in the lease
    database may be improperly deleted. if the dhcpd server
    binary was built for a 64-bit architecture OR if the
    -fstack-protection-strong compiler flag was NOT
    specified, the crash will not occur, but it is possible
    for the offending lease and the lease which immediately
    followed it to be improperly
    deleted.(CVE-2021-25217)Failure to properly
    bounds-check a buffer used for processing DHCP options
    allows a malicious server (or an entity masquerading as
    a server) to cause a buffer overflow (and resulting
    crash) in dhclient by sending a response containing a
    specially constructed options section. Affects ISC DHCP
    versions 4.1.0 -> 4.1-ESV-R15, 4.2.0 -> 4.2.8, 4.3.0 ->
    4.3.6, 4.4.0(CVE-2018-5732)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2077
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?50bfad39");
  script_set_attribute(attribute:"solution", value:
"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-5732");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.2.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["dhclient-4.2.5-68.1.h18",
        "dhcp-4.2.5-68.1.h18",
        "dhcp-common-4.2.5-68.1.h18",
        "dhcp-libs-4.2.5-68.1.h18"];

foreach (pkg in pkgs)
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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
