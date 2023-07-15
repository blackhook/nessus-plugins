##
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2021-0082. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147275);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/03/10");

  script_cve_id(
    "CVE-2018-10103",
    "CVE-2018-10105",
    "CVE-2018-14461",
    "CVE-2018-14462",
    "CVE-2018-14463",
    "CVE-2018-14464",
    "CVE-2018-14465",
    "CVE-2018-14466",
    "CVE-2018-14467",
    "CVE-2018-14468",
    "CVE-2018-14469",
    "CVE-2018-14470",
    "CVE-2018-14879",
    "CVE-2018-14880",
    "CVE-2018-14881",
    "CVE-2018-14882",
    "CVE-2018-16227",
    "CVE-2018-16228",
    "CVE-2018-16229",
    "CVE-2018-16230",
    "CVE-2018-16300",
    "CVE-2018-16451",
    "CVE-2018-16452",
    "CVE-2019-15166"
  );

  script_name(english:"NewStart CGSL MAIN 6.02 : tcpdump Multiple Vulnerabilities (NS-SA-2021-0082)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has tcpdump packages installed that are affected by multiple
vulnerabilities:

  - The ICMP parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp.c:icmp_print().
    (CVE-2018-14462)

  - The ICMPv6 parser in tcpdump before 4.9.3 has a buffer over-read in print-icmp6.c. (CVE-2018-14882)

  - The BGP parser in tcpdump before 4.9.3 allows stack consumption in print-bgp.c:bgp_attr_print() because of
    unlimited recursion. (CVE-2018-16300)

  - The IKEv1 parser in tcpdump before 4.9.3 has a buffer over-read in print-isakmp.c:ikev1_n_print().
    (CVE-2018-14469)

  - The RSVP parser in tcpdump before 4.9.3 has a buffer over-read in print-rsvp.c:rsvp_obj_print().
    (CVE-2018-14465)

  - The VRRP parser in tcpdump before 4.9.3 has a buffer over-read in print-vrrp.c:vrrp_print().
    (CVE-2018-14463)

  - The command-line argument parser in tcpdump before 4.9.3 has a buffer overflow in
    tcpdump.c:get_next_file(). (CVE-2018-14879)

  - The DCCP parser in tcpdump before 4.9.3 has a buffer over-read in print-dccp.c:dccp_print_option().
    (CVE-2018-16229)

  - The IEEE 802.11 parser in tcpdump before 4.9.3 has a buffer over-read in print-802_11.c for the Mesh Flags
    subfield. (CVE-2018-16227)

  - The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_RESTART). (CVE-2018-14881)

  - The FRF.16 parser in tcpdump before 4.9.3 has a buffer over-read in print-fr.c:mfr_print().
    (CVE-2018-14468)

  - The OSPFv3 parser in tcpdump before 4.9.3 has a buffer over-read in print-ospf6.c:ospf6_print_lshdr().
    (CVE-2018-14880)

  - The LDP parser in tcpdump before 4.9.3 has a buffer over-read in print-ldp.c:ldp_tlv_print().
    (CVE-2018-14461)

  - The LMP parser in tcpdump before 4.9.3 has a buffer over-read in print-
    lmp.c:lmp_print_data_link_subobjs(). (CVE-2018-14464)

  - The Rx parser in tcpdump before 4.9.3 has a buffer over-read in print-rx.c:rx_cache_find() and
    rx_cache_insert(). (CVE-2018-14466)

  - The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_MP). (CVE-2018-14467)

  - The Babel parser in tcpdump before 4.9.3 has a buffer over-read in print-babel.c:babel_print_v2().
    (CVE-2018-14470)

  - The HNCP parser in tcpdump before 4.9.3 has a buffer over-read in print-hncp.c:print_prefix().
    (CVE-2018-16228)

  - The BGP parser in tcpdump before 4.9.3 has a buffer over-read in print-bgp.c:bgp_attr_print()
    (MP_REACH_NLRI). (CVE-2018-16230)

  - The SMB parser in tcpdump before 4.9.3 has buffer over-reads in print-smb.c:print_trans() for
    \MAILSLOT\BROWSE and \PIPE\LANMAN. (CVE-2018-16451)

  - The SMB parser in tcpdump before 4.9.3 has stack exhaustion in smbutil.c:smb_fdata() via recursion.
    (CVE-2018-16452)

  - lmp_print_data_link_subobjs() in print-lmp.c in tcpdump before 4.9.3 lacks certain bounds checks.
    (CVE-2019-15166)

  - tcpdump before 4.9.3 mishandles the printing of SMB data (issue 1 of 2). (CVE-2018-10103)

  - tcpdump before 4.9.3 mishandles the printing of SMB data (issue 2 of 2). (CVE-2018-10105)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2021-0082");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL tcpdump packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10105");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('audit.inc');
include('global_settings.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

flag = 0;

pkgs = {
  'CGSL MAIN 6.02': [
    'tcpdump-4.9.3-1.el8',
    'tcpdump-debuginfo-4.9.3-1.el8',
    'tcpdump-debugsource-4.9.3-1.el8'
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'tcpdump');
}
