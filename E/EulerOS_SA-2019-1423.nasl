#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(124926);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-14491",
    "CVE-2017-14492",
    "CVE-2017-14493",
    "CVE-2017-14494",
    "CVE-2017-14495",
    "CVE-2017-14496"
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : dnsmasq (EulerOS-SA-2019-1423)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dnsmasq packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A heap buffer overflow was discovered in dnsmasq in the
    IPv6 router advertisement (RA) handling code. An
    attacker on the local network segment could send
    crafted RAs to dnsmasq which would cause it to crash
    or, potentially, execute arbitrary code. This issue
    only affected configurations using one of these
    options: enable-ra, ra-only, slaac, ra-names,
    ra-advrouter, or ra-stateless.(CVE-2017-14492)

  - An information leak was found in dnsmasq in the DHCPv6
    relay code. An attacker on the local network could send
    crafted DHCPv6 packets to dnsmasq causing it to forward
    the contents of process memory, potentially leaking
    sensitive data.(CVE-2017-14494)

  - A heap buffer overflow was found in dnsmasq in the code
    responsible for building DNS replies. An attacker could
    send crafted DNS packets to dnsmasq which would cause
    it to crash or, potentially, execute arbitrary
    code.(CVE-2017-14491)

  - A memory exhaustion flaw was found in dnsmasq in the
    EDNS0 code. An attacker could send crafted DNS packets
    which would trigger memory allocations which would
    never be freed, leading to unbounded memory consumption
    and eventually a crash. This issue only affected
    configurations using one of the options: add-mac,
    add-cpe-id, or add-subnet.(CVE-2017-14495)

  - An integer underflow flaw leading to a buffer over-read
    was found in dnsmasq in the EDNS0 code. An attacker
    could send crafted DNS packets to dnsmasq which would
    cause it to crash. This issue only affected
    configurations using one of the options: add-mac,
    add-cpe-id, or add-subnet.(CVE-2017-14496)

  - A stack buffer overflow was found in dnsmasq in the
    DHCPv6 code. An attacker on the local network could
    send a crafted DHCPv6 request to dnsmasq which would
    cause it to a crash or, potentially, execute arbitrary
    code.(CVE-2017-14493)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1423
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f08df9ff");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14493");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["dnsmasq-2.76-5.h2",
        "dnsmasq-utils-2.76-5.h2"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq");
}
