#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# @NOAGENT@
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 202305-22.
#
# The advisory text is Copyright (C) 2001-2021 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include('compat.inc');

if (description)
{
  script_id(175059);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/05/03");

  script_cve_id("CVE-2021-25217", "CVE-2022-2928", "CVE-2022-2929");

  script_name(english:"GLSA-202305-22 : ISC DHCP: Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by the vulnerability described in GLSA-202305-22 (ISC DHCP: Multiple Vulnerabilities)

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

  - In ISC DHCP 4.4.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1, when the function
    option_code_hash_lookup() is called from add_option(), it increases the option's refcount field. However,
    there is not a corresponding call to option_dereference() to decrement the refcount field. The function
    add_option() is only used in server responses to lease query packets. Each lease query response calls this
    function for several options, so eventually, the reference counters could overflow and cause the server to
    abort. (CVE-2022-2928)

  - In ISC DHCP 1.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1 a system with access to a DHCP server,
    sending DHCP packets crafted to include fqdn labels longer than 63 bytes, could eventually cause the
    server to run out of memory. (CVE-2022-2929)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.gentoo.org/glsa/202305-22");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=792324");
  script_set_attribute(attribute:"see_also", value:"https://bugs.gentoo.org/show_bug.cgi?id=875521");
  script_set_attribute(attribute:"solution", value:
"All ISC DHCP users should upgrade to the latest version:

          # emerge --sync
          # emerge --ask --oneshot --verbose >=net-misc/dhcp-4.4.3_p1");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/05/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Gentoo Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}
include('qpkg.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/Gentoo/release')) audit(AUDIT_OS_NOT, 'Gentoo');
if (!get_kb_item('Host/Gentoo/qpkg-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var flag = 0;

var packages = [
  {
    'name' : 'net-misc/dhcp',
    'unaffected' : make_list("ge 4.4.3_p1"),
    'vulnerable' : make_list("lt 4.4.3_p1")
  }
];

foreach var package( packages ) {
  if (isnull(package['unaffected'])) package['unaffected'] = make_list();
  if (isnull(package['vulnerable'])) package['vulnerable'] = make_list();
  if (qpkg_check(package: package['name'] , unaffected: package['unaffected'], vulnerable: package['vulnerable'])) flag++;
}


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : qpkg_report_get()
  );
  exit(0);
}
else
{
  qpkg_tests = list_uniq(qpkg_tests);
  var tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ISC DHCP');
}
