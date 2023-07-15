#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131900);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2016-1245",
    "CVE-2016-2342",
    "CVE-2016-4049",
    "CVE-2017-3224",
    "CVE-2018-5380",
    "CVE-2018-5381"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0227");

  script_name(english:"EulerOS 2.0 SP2 : quagga (EulerOS-SA-2019-2408)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the quagga package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Open Shortest Path First (OSPF) protocol
    implementations may improperly determine Link State
    Advertisement (LSA) recency for LSAs with
    MaxSequenceNumber. According to RFC 2328 section 13.1,
    for two instances of the same LSA, recency is
    determined by first comparing sequence numbers, then
    checksums, and finally MaxAge. In a case where the
    sequence numbers are the same, the LSA with the larger
    checksum is considered more recent, and will not be
    flushed from the Link State Database (LSDB). Since the
    RFC does not explicitly state that the values of links
    carried by a LSA must be the same when prematurely
    aging a self-originating LSA with MaxSequenceNumber, it
    is possible in vulnerable OSPF implementations for an
    attacker to craft a LSA with MaxSequenceNumber and
    invalid links that will result in a larger checksum and
    thus a 'newer' LSA that will not be flushed from the
    LSDB. Propagation of the crafted LSA can result in the
    erasure or alteration of the routing tables of routers
    within the routing domain, creating a denial of service
    condition or the re-routing of traffic on the network.
    CVE-2017-3224 has been reserved for Quagga and
    downstream implementations (SUSE, openSUSE, and Red Hat
    packages).(CVE-2017-3224)

  - The bgp_dump_routes_func function in bgpd/bgp_dump.c in
    Quagga does not perform size checks when dumping data,
    which might allow remote attackers to cause a denial of
    service (assertion failure and daemon crash) via a
    large BGP packet.(CVE-2016-4049)

  - The bgp_nlri_parse_vpnv4 function in bgp_mplsvpn.c in
    the VPNv4 NLRI parser in bgpd in Quagga before
    1.0.20160309, when a certain VPNv4 configuration is
    used, relies on a Labeled-VPN SAFI routes-data length
    field during a data copy, which allows remote attackers
    to execute arbitrary code or cause a denial of service
    (stack-based buffer overflow) via a crafted
    packet.(CVE-2016-2342)

  - The Quagga BGP daemon (bgpd) prior to version 1.2.3 can
    overrun internal BGP code-to-string conversion tables
    used for debug by 1 pointer value, based on
    input.(CVE-2018-5380)

  - The Quagga BGP daemon (bgpd) prior to version 1.2.3 has
    a bug in its parsing of 'Capabilities' in BGP OPEN
    messages, in the bgp_packet.c:bgp_capability_msg_parse
    function. The parser can enter an infinite loop on
    invalid capabilities if a Multi-Protocol capability
    does not have a recognized AFI/SAFI, causing a denial
    of service.(CVE-2018-5381)

  - It was discovered that the zebra daemon in Quagga
    before 1.0.20161017 suffered from a stack-based buffer
    overflow when processing IPv6 Neighbor Discovery
    messages. The root cause was relying on BUFSIZ to be
    compatible with a message size however, BUFSIZ is
    system-dependent.(CVE-2016-1245)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2408
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a16c956b");
  script_set_attribute(attribute:"solution", value:
"Update the affected quagga packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-2342");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-1245");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:quagga");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["quagga-0.99.22.4-5.h6"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "quagga");
}
