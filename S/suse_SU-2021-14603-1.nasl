#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2021:14603-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150612);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id(
    "CVE-2019-14834",
    "CVE-2020-25681",
    "CVE-2020-25682",
    "CVE-2020-25683",
    "CVE-2020-25684",
    "CVE-2020-25685",
    "CVE-2020-25686",
    "CVE-2020-25687"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2021:14603-1");
  script_xref(name:"IAVA", value:"2020-A-0194-S");
  script_xref(name:"IAVA", value:"2021-A-0041");
  script_xref(name:"CEA-ID", value:"CEA-2021-0003");

  script_name(english:"SUSE SLES11 Security Update : dnsmasq (SUSE-SU-2021:14603-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES11 host has a package installed that is affected by multiple vulnerabilities as referenced in
the SUSE-SU-2021:14603-1 advisory.

  - A vulnerability was found in dnsmasq before version 2.81, where the memory leak allows remote attackers to
    cause a denial of service (memory consumption) via vectors involving DHCP response creation.
    (CVE-2019-14834)

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
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1154849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176076");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1177077");
  # https://lists.suse.com/pipermail/sle-security-updates/2021-January/008224.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb2f7f83");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-14834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25681");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25682");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25683");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25684");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25685");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-25687");
  script_set_attribute(attribute:"solution", value:
"Update the affected dnsmasq package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25682");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/01/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dnsmasq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES11', 'SUSE ' + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE ' + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP4", os_ver + " SP" + sp);

pkgs = [
    {'reference':'dnsmasq-2.78-0.17.15', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'SLES_SAP-release-11.4'},
    {'reference':'dnsmasq-2.78-0.17.15', 'sp':'4', 'release':'SLES11', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'sles-release-11.4'}
];

flag = 0;
foreach package_array ( pkgs ) {
  reference = NULL;
  release = NULL;
  sp = NULL;
  cpu = NULL;
  exists_check = NULL;
  rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release && exists_check) {
    if (rpm_exists(release:release, rpm:exists_check) && rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
  else if (reference && release) {
    if (rpm_check(release:release, sp:sp, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'dnsmasq');
}
