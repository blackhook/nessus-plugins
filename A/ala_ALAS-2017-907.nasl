#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2017-907.
#

include("compat.inc");

if (description)
{
  script_id(103604);
  script_version("3.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/05/08");

  script_cve_id("CVE-2017-14491", "CVE-2017-14492", "CVE-2017-14493", "CVE-2017-14494", "CVE-2017-14495", "CVE-2017-14496");
  script_xref(name:"ALAS", value:"2017-907");
  script_xref(name:"IAVA", value:"2017-A-0284-S");

  script_name(english:"Amazon Linux AMI : dnsmasq (ALAS-2017-907)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Information leak in the DHCPv6 relay code

An information leak was found in dnsmasq in the DHCPv6 relay code. An
attacker on the local network could send crafted DHCPv6 packets to
dnsmasq causing it to forward the contents of process memory,
potentially leaking sensitive data. (CVE-2017-14494)

Memory exhaustion vulnerability in the EDNS0 code

A memory exhaustion flaw was found in dnsmasq in the EDNS0 code. An
attacker could send crafted DNS packets which would trigger memory
allocations which would never be freed, leading to unbounded memory
consumption and eventually a crash. This issue only affected
configurations using one of the options: add-mac, add-cpe-id, or
add-subnet. (CVE-2017-14495)

Integer underflow leading to buffer over-read in the EDNS0 code

An integer underflow flaw leading to a buffer over-read was found in
dnsmasq in the EDNS0 code. An attacker could send crafted DNS packets
to dnsmasq which would cause it to crash. This issue only affected
configurations using one of the options: add-mac, add-cpe-id, or
add-subnet. (CVE-2017-14496)

Heap overflow in the code responsible for building DNS replies

A heap buffer overflow was found in dnsmasq in the code responsible
for building DNS replies. An attacker could send crafted DNS packets
to dnsmasq which would cause it to crash or, potentially, execute
arbitrary code. (CVE-2017-14491)

Heap overflow in the IPv6 router advertisement code

A heap buffer overflow was discovered in dnsmasq in the IPv6 router
advertisement (RA) handling code. An attacker on the local network
segment could send crafted RAs to dnsmasq which would cause it to
crash or, potentially, execute arbitrary code. This issue only
affected configurations using one of these options: enable-ra,
ra-only, slaac, ra-names, ra-advrouter, or ra-stateless.
(CVE-2017-14492)

Stack buffer overflow in the DHCPv6 code

A stack buffer overflow was found in dnsmasq in the DHCPv6 code. An
attacker on the local network could send a crafted DHCPv6 request to
dnsmasq which would cause it to a crash or, potentially, execute
arbitrary code. (CVE-2017-14493)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2017-907.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update dnsmasq' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dnsmasq-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:dnsmasq-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/03");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "A")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux AMI", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"dnsmasq-2.76-2.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dnsmasq-debuginfo-2.76-2.14.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"dnsmasq-utils-2.76-2.14.amzn1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dnsmasq / dnsmasq-debuginfo / dnsmasq-utils");
}
