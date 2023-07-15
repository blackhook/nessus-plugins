#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(158024);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/13");

  script_cve_id(
    "CVE-2019-25031",
    "CVE-2019-25032",
    "CVE-2019-25033",
    "CVE-2019-25034",
    "CVE-2019-25035",
    "CVE-2019-25036",
    "CVE-2019-25037",
    "CVE-2019-25038",
    "CVE-2019-25039",
    "CVE-2019-25040",
    "CVE-2019-25041",
    "CVE-2019-25042"
  );

  script_name(english:"EulerOS Virtualization 3.0.6.0 : unbound (EulerOS-SA-2022-1100)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the unbound packages installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - ** DISPUTED ** Unbound before 1.9.5 allows configuration injection in create_unbound_ad_servers.sh upon a
    successful man-in-the-middle attack against a cleartext HTTP session. NOTE: The vendor does not consider
    this a vulnerability of the Unbound software. create_unbound_ad_servers.sh is a contributed script from
    the community that facilitates automatic configuration creation. It is not part of the Unbound
    installation. (CVE-2019-25031)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in the regional allocator via
    regional_alloc. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25032)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in the regional allocator via the ALIGN_UP
    macro. NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a
    running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25033)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in sldns_str2wire_dname_buf_origin, leading
    to an out-of-bounds write. NOTE: The vendor disputes that this is a vulnerability. Although the code may
    be vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25034)

  - ** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write in sldns_bget_token_par. NOTE: The
    vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25035)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in synth_cname.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25036)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure and denial of service in dname_pkt_copy
    via an invalid packet. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25037)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in
    dnscrypt/dnscrypt.c. NOTE: The vendor disputes that this is a vulnerability. Although the code may be
    vulnerable, a running Unbound installation cannot be remotely or locally exploited. (CVE-2019-25038)

  - ** DISPUTED ** Unbound before 1.9.5 allows an integer overflow in a size calculation in respip/respip.c.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25039)

  - ** DISPUTED ** Unbound before 1.9.5 allows an infinite loop via a compressed name in dname_pkt_copy. NOTE:
    The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running Unbound
    installation cannot be remotely or locally exploited. (CVE-2019-25040)

  - ** DISPUTED ** Unbound before 1.9.5 allows an assertion failure via a compressed name in dname_pkt_copy.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25041)

  - ** DISPUTED ** Unbound before 1.9.5 allows an out-of-bounds write via a compressed name in rdata_copy.
    NOTE: The vendor disputes that this is a vulnerability. Although the code may be vulnerable, a running
    Unbound installation cannot be remotely or locally exploited. (CVE-2019-25042)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2022-1100
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?13dbc7cd");
  script_set_attribute(attribute:"solution", value:
"Update the affected unbound packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-25042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python2-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:unbound-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "python2-unbound-1.7.3-9.h6.eulerosv2r8",
  "python3-unbound-1.7.3-9.h6.eulerosv2r8",
  "unbound-1.7.3-9.h6.eulerosv2r8",
  "unbound-libs-1.7.3-9.h6.eulerosv2r8"
];

foreach (var pkg in pkgs)
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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "unbound");
}
