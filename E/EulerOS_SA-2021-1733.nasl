#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(148613);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2020-25681",
    "CVE-2020-25682",
    "CVE-2020-25683",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686",
    "CVE-2020-25687"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"EulerOS Virtualization 2.9.1 : dnsmasq (EulerOS-SA-2021-1733)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dnsmasq package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A flaw was found in dnsmasq. A heap-based buffer
    overflow was discovered in dnsmasq when DNSSEC is
    enabled and before it validates the received DNS
    entries. This flaw allows a remote attacker, who can
    create valid DNS replies, to cause an overflow in a
    heap-allocated memory. This flaw is caused by the lack
    of length checks in rfc1035.c:extract_name(), which
    could be abused to make the code execute memcpy() with
    a negative size in sort_rrset() and cause a crash in
    dnsmasq, resulting in a denial of service. The highest
    threat from this vulnerability is to system
    availability.(CVE-2020-25687)

  - A flaw was found in dnsmasq. When receiving a query,
    dnsmasq does not check for an existing pending request
    for the same name and forwards a new request. By
    default, a maximum of 150 pending queries can be sent
    to upstream servers, so there can be at most 150
    queries for the same name. This flaw allows an off-path
    attacker on the network to substantially reduce the
    number of attempts that it would have to perform to
    forge a reply and have it accepted by dnsmasq. This
    issue is mentioned in the 'Birthday Attacks' section of
    RFC5452. If chained with CVE-2020-25684, the attack
    complexity of a successful attack is reduced. The
    highest threat from this vulnerability is to data
    integrity.(CVE-2020-25686)

  - A flaw was found in dnsmasq. When getting a reply from
    a forwarded query, dnsmasq checks in
    forward.c:reply_query(), which is the forwarded query
    that matches the reply, by only using a weak hash of
    the query name. Due to the weak hash (CRC32 when
    dnsmasq is compiled without DNSSEC, SHA-1 when it is)
    this flaw allows an off-path attacker to find several
    different domains all having the same hash,
    substantially reducing the number of attempts they
    would have to perform to forge a reply and get it
    accepted by dnsmasq. This is in contrast with RFC5452,
    which specifies that the query name is one of the
    attributes of a query that must be used to match a
    reply. This flaw could be abused to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25684 the
    attack complexity of a successful attack is reduced.
    The highest threat from this vulnerability is to data
    integrity.(CVE-2020-25685)

  - A flaw was found in dnsmasq. When getting a reply from
    a forwarded query, dnsmasq checks in the
    forward.c:reply_query() if the reply destination
    address/port is used by the pending forwarded queries.
    However, it does not use the address/port to retrieve
    the exact forwarded query, substantially reducing the
    number of attempts an attacker on the network would
    have to perform to forge a reply and get it accepted by
    dnsmasq. This issue contrasts with RFC5452, which
    specifies a query's attributes that all must be used to
    match a reply. This flaw allows an attacker to perform
    a DNS Cache Poisoning attack. If chained with
    CVE-2020-25685 or CVE-2020-25686, the attack complexity
    of a successful attack is reduced. The highest threat
    from this vulnerability is to data
    integrity.(CVE-2020-25684)

  - A flaw was found in dnsmasq. A heap-based buffer
    overflow was discovered in dnsmasq when DNSSEC is
    enabled and before it validates the received DNS
    entries. A remote attacker, who can create valid DNS
    replies, could use this flaw to cause an overflow in a
    heap-allocated memory. This flaw is caused by the lack
    of length checks in rfc1035.c:extract_name(), which
    could be abused to make the code execute memcpy() with
    a negative size in get_rdata() and cause a crash in
    dnsmasq, resulting in a denial of service. The highest
    threat from this vulnerability is to system
    availability.(CVE-2020-25683)

  - A flaw was found in dnsmasq. A buffer overflow
    vulnerability was discovered in the way dnsmasq extract
    names from DNS packets before validating them with
    DNSSEC data. An attacker on the network, who can create
    valid DNS replies, could use this flaw to cause an
    overflow with arbitrary data in a heap-allocated
    memory, possibly executing code on the machine. The
    flaw is in the rfc1035.c:extract_name() function, which
    writes data to the memory pointed by name assuming
    MAXDNAME*2 bytes are available in the buffer. However,
    in some code execution paths, it is possible
    extract_name() gets passed an offset from the base
    buffer, thus reducing, in practice, the number of
    available bytes that can be written in the buffer. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25682)

  - A flaw was found in dnsmasq. A heap-based buffer
    overflow was discovered in the way RRSets are sorted
    before validating with DNSSEC data. An attacker on the
    network, who can forge DNS replies such as that they
    are accepted as valid, could use this flaw to cause a
    buffer overflow with arbitrary data in a heap memory
    segment, possibly executing code on the machine. The
    highest threat from this vulnerability is to data
    confidentiality and integrity as well as system
    availability.(CVE-2020-25681)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1733
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6a9a7d34");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["dnsmasq-2.81-1.h6.eulerosv2r9"];

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
