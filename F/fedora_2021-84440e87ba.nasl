##
# (C) Tenable Network Security, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2021-84440e87ba
#

include('compat.inc');

if (description)
{
  script_id(145241);
  script_version("1.6");
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
  script_xref(name:"FEDORA", value:"2021-84440e87ba");
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"Fedora 33 : dnsmasq (2021-84440e87ba)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 33 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2021-84440e87ba advisory.

  - A flaw was found in dnsmasq before version 2.83. A heap-based buffer overflow was discovered in the way
    RRSets are sorted before validating with DNSSEC data. An attacker on the network, who can forge DNS
    replies such as that they are accepted as valid, could use this flaw to cause a buffer overflow with
    arbitrary data in a heap memory segment, possibly executing code on the machine. The highest threat from
    this vulnerability is to data confidentiality and integrity as well as system availability.
    (CVE-2020-25681)

  - A flaw was found in dnsmasq before 2.83. A buffer overflow vulnerability was discovered in the way dnsmasq
    extract names from DNS packets before validating them with DNSSEC data. An attacker on the network, who
    can create valid DNS replies, could use this flaw to cause an overflow with arbitrary data in a heap-
    allocated memory, possibly executing code on the machine. The flaw is in the rfc1035.c:extract_name()
    function, which writes data to the memory pointed by name assuming MAXDNAME*2 bytes are available in the
    buffer. However, in some code execution paths, it is possible extract_name() gets passed an offset from
    the base buffer, thus reducing, in practice, the number of available bytes that can be written in the
    buffer. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2020-25682)

  - A flaw was found in dnsmasq before version 2.83. A heap-based buffer overflow was discovered in dnsmasq
    when DNSSEC is enabled and before it validates the received DNS entries. A remote attacker, who can create
    valid DNS replies, could use this flaw to cause an overflow in a heap-allocated memory. This flaw is
    caused by the lack of length checks in rfc1035.c:extract_name(), which could be abused to make the code
    execute memcpy() with a negative size in get_rdata() and cause a crash in dnsmasq, resulting in a denial
    of service. The highest threat from this vulnerability is to system availability. (CVE-2020-25683)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in the forward.c:reply_query() if the reply destination address/port is used by the pending
    forwarded queries. However, it does not use the address/port to retrieve the exact forwarded query,
    substantially reducing the number of attempts an attacker on the network would have to perform to forge a
    reply and get it accepted by dnsmasq. This issue contrasts with RFC5452, which specifies a query's
    attributes that all must be used to match a reply. This flaw allows an attacker to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25685 or CVE-2020-25686, the attack complexity of a successful
    attack is reduced. The highest threat from this vulnerability is to data integrity. (CVE-2020-25684)

  - A flaw was found in dnsmasq before version 2.83. When getting a reply from a forwarded query, dnsmasq
    checks in forward.c:reply_query(), which is the forwarded query that matches the reply, by only using a
    weak hash of the query name. Due to the weak hash (CRC32 when dnsmasq is compiled without DNSSEC, SHA-1
    when it is) this flaw allows an off-path attacker to find several different domains all having the same
    hash, substantially reducing the number of attempts they would have to perform to forge a reply and get it
    accepted by dnsmasq. This is in contrast with RFC5452, which specifies that the query name is one of the
    attributes of a query that must be used to match a reply. This flaw could be abused to perform a DNS Cache
    Poisoning attack. If chained with CVE-2020-25684 the attack complexity of a successful attack is reduced.
    The highest threat from this vulnerability is to data integrity. (CVE-2020-25685)

  - A flaw was found in dnsmasq before version 2.83. When receiving a query, dnsmasq does not check for an
    existing pending request for the same name and forwards a new request. By default, a maximum of 150
    pending queries can be sent to upstream servers, so there can be at most 150 queries for the same name.
    This flaw allows an off-path attacker on the network to substantially reduce the number of attempts that
    it would have to perform to forge a reply and have it accepted by dnsmasq. This issue is mentioned in the
    Birthday Attacks section of RFC5452. If chained with CVE-2020-25684, the attack complexity of a
    successful attack is reduced. The highest threat from this vulnerability is to data integrity.
    (CVE-2020-25686)

  - A flaw was found in dnsmasq before version 2.83. A heap-based buffer overflow was discovered in dnsmasq
    when DNSSEC is enabled and before it validates the received DNS entries. This flaw allows a remote
    attacker, who can create valid DNS replies, to cause an overflow in a heap-allocated memory. This flaw is
    caused by the lack of length checks in rfc1035.c:extract_name(), which could be abused to make the code
    execute memcpy() with a negative size in sort_rrset() and cause a crash in dnsmasq, resulting in a denial
    of service. The highest threat from this vulnerability is to system availability. (CVE-2020-25687)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2021-84440e87ba");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dnsmasq");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item('Host/RedHat/release');
if (isnull(release) || 'Fedora' >!< release) audit(AUDIT_OS_NOT, 'Fedora');
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^33([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 33', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

pkgs = [
    {'reference':'dnsmasq-2.83-1.fc33', 'release':'FC33', 'rpm_spec_vers_cmp':TRUE}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  el_string = NULL;
  rpm_spec_vers_cmp = NULL;
  epoch = NULL;
  allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq');
}
