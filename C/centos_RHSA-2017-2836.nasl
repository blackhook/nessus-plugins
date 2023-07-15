#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:2836 and 
# CentOS Errata and Security Advisory 2017:2836 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(103605);
  script_version("3.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/04");

  script_cve_id("CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_xref(name:"RHSA", value:"2017:2836");
  script_xref(name:"IAVA", value:"2017-A-0284-S");

  script_name(english:"CentOS 7 : dnsmasq (CESA-2017:2836)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for dnsmasq is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Critical. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The dnsmasq packages contain Dnsmasq, a lightweight DNS (Domain Name
Server) forwarder and DHCP (Dynamic Host Configuration Protocol)
server.

Security Fix(es) :

* A heap buffer overflow was found in dnsmasq in the code responsible
for building DNS replies. An attacker could send crafted DNS packets
to dnsmasq which would cause it to crash or, potentially, execute
arbitrary code. (CVE-2017-14491)

* A heap buffer overflow was discovered in dnsmasq in the IPv6 router
advertisement (RA) handling code. An attacker on the local network
segment could send crafted RAs to dnsmasq which would cause it to
crash or, potentially, execute arbitrary code. This issue only
affected configurations using one of these options: enable-ra,
ra-only, slaac, ra-names, ra-advrouter, or ra-stateless.
(CVE-2017-14492)

* A stack-based buffer overflow was found in dnsmasq in the DHCPv6
code. An attacker on the local network could send a crafted DHCPv6
request to dnsmasq which would cause it to a crash or, potentially,
execute arbitrary code. (CVE-2017-14493)

* An information leak was found in dnsmasq in the DHCPv6 relay code.
An attacker on the local network could send crafted DHCPv6 packets to
dnsmasq causing it to forward the contents of process memory,
potentially leaking sensitive data. (CVE-2017-14494)

* A memory exhaustion flaw was found in dnsmasq in the EDNS0 code. An
attacker could send crafted DNS packets which would trigger memory
allocations which would never be freed, leading to unbounded memory
consumption and eventually a crash. This issue only affected
configurations using one of the options: add-mac, add-cpe-id, or
add-subnet. (CVE-2017-14495)

* An integer underflow flaw leading to a buffer over-read was found in
dnsmasq in the EDNS0 code. An attacker could send crafted DNS packets
to dnsmasq which would cause it to crash. This issue only affected
configurations using one of the options: add-mac, add-cpe-id, or
add-subnet. (CVE-2017-14496)

Red Hat would like to thank Felix Wilhelm (Google Security Team),
Fermin J. Serna (Google Security Team), Gabriel Campana (Google
Security Team), Kevin Hamacher (Google Security Team), and Ron Bowes
(Google Security Team) for reporting these issues."
  );
  # https://lists.centos.org/pipermail/centos-announce/2017-October/022555.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?5ce1d581"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected dnsmasq packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-14496");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dnsmasq-2.76-2.el7_4.2")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"dnsmasq-utils-2.76-2.el7_4.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq / dnsmasq-utils");
}
