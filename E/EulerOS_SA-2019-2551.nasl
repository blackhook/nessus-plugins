#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131825);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/29");

  script_cve_id(
    "CVE-2018-14461",
    "CVE-2018-14462",
    "CVE-2018-14463",
    "CVE-2018-14464",
    "CVE-2018-14465",
    "CVE-2018-14466",
    "CVE-2018-14467",
    "CVE-2018-14469",
    "CVE-2018-14470",
    "CVE-2018-14879",
    "CVE-2018-14880",
    "CVE-2018-14881",
    "CVE-2018-16227",
    "CVE-2018-16229",
    "CVE-2018-16230",
    "CVE-2018-16300",
    "CVE-2018-16451",
    "CVE-2018-16452"
  );

  script_name(english:"EulerOS 2.0 SP5 : tcpdump (EulerOS-SA-2019-2551)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the tcpdump package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The LDP parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-ldp.c:ldp_tlv_print().(CVE-2018-14461)

  - The ICMP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-icmp.c:icmp_print().(CVE-2018-14462)

  - The VRRP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-vrrp.c:vrrp_print().(CVE-2018-14463)

  - The LMP parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-lmp.c:lmp_print_data_link_subobjs().(CVE-2018-144
    64)

  - The RSVP parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-rsvp.c:rsvp_obj_print().(CVE-2018-14465)

  - The Rx parser in tcpdump before 4.9.3 has a buffer
    over-read in print-rx.c:rx_cache_find() and
    rx_cache_insert().(CVE-2018-14466)

  - The BGP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_MP).(CVE-2018-14467)

  - The IKEv1 parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-isakmp.c:ikev1_n_print().(CVE-2018-14469)

  - The Babel parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-babel.c:babel_print_v2().(CVE-2018-14470)

  - The command-line argument parser in tcpdump before
    4.9.3 has a buffer overflow in
    tcpdump.c:get_next_file().(CVE-2018-14879)

  - The OSPFv3 parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-ospf6.c:ospf6_print_lshdr().(CVE-2018-14880)

  - The BGP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-bgp.c:bgp_capabilities_print()
    (BGP_CAPCODE_RESTART).(CVE-2018-14881)

  - The IEEE 802.11 parser in tcpdump before 4.9.3 has a
    buffer over-read in print-802_11.c for the Mesh Flags
    subfield.(CVE-2018-16227)

  - The DCCP parser in tcpdump before 4.9.3 has a buffer
    over-read in
    print-dccp.c:dccp_print_option().(CVE-2018-16229)

  - The BGP parser in tcpdump before 4.9.3 has a buffer
    over-read in print-bgp.c:bgp_attr_print()
    (MP_REACH_NLRI).(CVE-2018-16230)

  - The BGP parser in tcpdump before 4.9.3 allows stack
    consumption in print-bgp.c:bgp_attr_print() because of
    unlimited recursion.(CVE-2018-16300)

  - The SMB parser in tcpdump before 4.9.3 has buffer
    over-reads in print-smb.c:print_trans() for
    \MAILSLOT\BROWSE and \PIPE\LANMAN.(CVE-2018-16451)

  - The SMB parser in tcpdump before 4.9.3 has stack
    exhaustion in smbutil.c:smb_fdata() via
    recursion.(CVE-2018-16452)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2551
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6997f598");
  script_set_attribute(attribute:"solution", value:
"Update the affected tcpdump packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14879");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:tcpdump");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["tcpdump-4.9.2-3.h2.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "tcpdump");
}
