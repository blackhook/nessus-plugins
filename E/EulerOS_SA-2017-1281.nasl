#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104334);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id(
    "CVE-2017-12894",
    "CVE-2017-12895",
    "CVE-2017-12897",
    "CVE-2017-12900",
    "CVE-2017-12901",
    "CVE-2017-12902",
    "CVE-2017-12985",
    "CVE-2017-12986",
    "CVE-2017-12987",
    "CVE-2017-12988",
    "CVE-2017-12989",
    "CVE-2017-12990",
    "CVE-2017-12991",
    "CVE-2017-12992",
    "CVE-2017-12993",
    "CVE-2017-12994",
    "CVE-2017-12995",
    "CVE-2017-12996",
    "CVE-2017-12997",
    "CVE-2017-12998",
    "CVE-2017-12999",
    "CVE-2017-13000",
    "CVE-2017-13001",
    "CVE-2017-13002",
    "CVE-2017-13003",
    "CVE-2017-13004",
    "CVE-2017-13005",
    "CVE-2017-13006",
    "CVE-2017-13007",
    "CVE-2017-13008",
    "CVE-2017-13009",
    "CVE-2017-13010",
    "CVE-2017-13011",
    "CVE-2017-13012",
    "CVE-2017-13013",
    "CVE-2017-13014",
    "CVE-2017-13015",
    "CVE-2017-13016",
    "CVE-2017-13017",
    "CVE-2017-13018",
    "CVE-2017-13019",
    "CVE-2017-13020",
    "CVE-2017-13021",
    "CVE-2017-13022",
    "CVE-2017-13023",
    "CVE-2017-13024",
    "CVE-2017-13025",
    "CVE-2017-13026",
    "CVE-2017-13027",
    "CVE-2017-13028",
    "CVE-2017-13029",
    "CVE-2017-13030",
    "CVE-2017-13031",
    "CVE-2017-13032",
    "CVE-2017-13033",
    "CVE-2017-13034",
    "CVE-2017-13035",
    "CVE-2017-13036",
    "CVE-2017-13037",
    "CVE-2017-13038",
    "CVE-2017-13039",
    "CVE-2017-13040",
    "CVE-2017-13041",
    "CVE-2017-13042",
    "CVE-2017-13043",
    "CVE-2017-13044",
    "CVE-2017-13045",
    "CVE-2017-13046",
    "CVE-2017-13047",
    "CVE-2017-13048",
    "CVE-2017-13049",
    "CVE-2017-13050",
    "CVE-2017-13051",
    "CVE-2017-13052",
    "CVE-2017-13053",
    "CVE-2017-13054",
    "CVE-2017-13055",
    "CVE-2017-13688",
    "CVE-2017-13689",
    "CVE-2017-13690",
    "CVE-2017-13725"
  );

  script_name(english:"EulerOS 2.0 SP2 : tcpdump (EulerOS-SA-2017-1281)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tcpdump package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The RSVP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-rsvp.c:rsvp_obj_print().(CVE-2017-13048)

  - The ARP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-arp.c, several
    functions.(CVE-2017-13013)

  - The VTP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-vtp.c:vtp_print().(CVE-2017-13033)

  - The OSPFv3 parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-ospf6.c:ospf6_decode_v3().(CVE-2017-13036)

  - The ISO ES-IS parser in tcpdump before 4.9.2 has a
    buffer over-read in
    print-isoclns.c:esis_print().(CVE-2017-13047)

  - The IPv6 mobility parser in tcpdump before 4.9.2 has a
    buffer over-read in
    print-mobility.c:mobility_opt_print().(CVE-2017-13025)

  - The PGM parser in tcpdump before 4.9.2 has a buffer
    over-read in print-pgm.c:pgm_print().(CVE-2017-13019)

  - The IPv6 parser in tcpdump before 4.9.2 has a buffer
    over-read in print-ip6.c:ip6_print().(CVE-2017-12985)

  - The IPv6 routing header parser in tcpdump before 4.9.2
    has a buffer over-read in
    print-rt6.c:rt6_print().(CVE-2017-13725)

  - The telnet parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-telnet.c:telnet_parse().(CVE-2017-12988)

  - The BGP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-bgp.c:bgp_attr_print().(CVE-2017-12991)

  - The MPTCP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-mptcp.c, several
    functions.(CVE-2017-13040)

  - The PPP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-ppp.c:print_ccp_config_options().(CVE-2017-13029)

  - The IEEE 802.15.4 parser in tcpdump before 4.9.2 has a
    buffer over-read in
    print-802_15_4.c:ieee802_15_4_if_print().(CVE-2017-1300
    0)

  - The IP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-ip.c:ip_printroute().(CVE-2017-13022)

  - The ISAKMP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-isakmp.c, several
    functions.(CVE-2017-13039)

  - The IPv6 fragmentation header parser in tcpdump before
    4.9.2 has a buffer over-read in
    print-frag6.c:frag6_print().(CVE-2017-13031)

  - The PIM parser in tcpdump before 4.9.2 has a buffer
    over-read in print-pim.c, several
    functions.(CVE-2017-13030)

  - The BGP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-bgp.c:bgp_attr_print().(CVE-2017-12994)

  - The BGP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-bgp.c:decode_multicast_vpn().(CVE-2017-13043)

  - The VQP parser in tcpdump before 4.9.2 has a buffer
    over-read in print-vqp.c:vqp_print().(CVE-2017-13045)

  - The LLDP parser in tcpdump before 4.9.2 has a buffer
    over-read in
    print-lldp.c:lldp_private_8023_print().(CVE-2017-13054,
    CVE-2017-12998,CVE-2017-13014,CVE-2017-13037,
    CVE-2017-13690,CVE-2017-13017,CVE-2017-12895,CVE-2017-1
    3046,CVE-2017-13688,CVE-2017-13053,CVE-2017-12995,CVE-2
    017-12997,CVE-2017-13016,CVE-2017-13002,CVE-2017-12989,
    CVE-2017-12999,CVE-2017-12900,CVE-2017-13006,CVE-2017-1
    2897,CVE-2017-13003,CVE-2017-12901,CVE-2017-13035,CVE-2
    017-13009,CVE-2017-13032,CVE-2017-13049,CVE-2017-13007,
    CVE-2017-13041,CVE-2017-12987,CVE-2017-12993,CVE-2017-1
    3023,CVE-2017-13026,CVE-2017-13055,CVE-2017-13042,CVE-2
    017-13018,CVE-2017-13044,CVE-2017-13012,CVE-2017-13001,
    CVE-2017-13050,CVE-2017-13028,CVE-2017-13024,CVE-2017-1
    2992,CVE-2017-13004,CVE-2017-13027,CVE-2017-13008,CVE-2
    017-13051,CVE-2017-13020,CVE-2017-12902,CVE-2017-13689,
    CVE-2017-13005,CVE-2017-12894,CVE-2017-13015,CVE-2017-1
    3038,CVE-2017-12990,CVE-2017-13034,CVE-2017-13011,CVE-2
    017-13021,CVE-2017-13010,CVE-2017-12986,CVE-2017-12996,
    CVE-2017-13052)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2017-1281
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5056afaf");
  script_set_attribute(attribute:"solution", value:
"Update the affected tcpdump packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["tcpdump-4.9.0-5.h175"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
