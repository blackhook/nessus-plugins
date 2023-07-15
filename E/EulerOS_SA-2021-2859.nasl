#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(156508);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/01/06");

  script_cve_id(
    "CVE-2018-25009",
    "CVE-2018-25011",
    "CVE-2018-25012",
    "CVE-2018-25013",
    "CVE-2018-25014",
    "CVE-2020-36328",
    "CVE-2020-36329",
    "CVE-2020-36331"
  );

  script_name(english:"EulerOS Virtualization 3.0.2.6 : libwebp (EulerOS-SA-2021-2859)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libwebp package installed, the EulerOS Virtualization installation on the remote host
is affected by the following vulnerabilities :

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    WebPMuxCreateInternal. The highest threat from this vulnerability is to data confidentiality and to the
    service availability. (CVE-2018-25009, CVE-2018-25012)

  - A flaw was found in libwebp in versions before 1.0.1. A heap-based buffer overflow was found in PutLE16().
    The highest threat from this vulnerability is to data confidentiality and integrity as well as system
    availability. (CVE-2018-25011)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ShiftBytes. The highest threat from this vulnerability is to data confidentiality and to the service
    availability. (CVE-2018-25013)

  - A flaw was found in libwebp in versions before 1.0.1. An unitialized variable is used in function
    ReadSymbol. The highest threat from this vulnerability is to data confidentiality and integrity as well as
    system availability. (CVE-2018-25014)

  - A flaw was found in libwebp in versions before 1.0.1. A heap-based buffer overflow in function
    WebPDecodeRGBInto is possible due to an invalid check for buffer size. The highest threat from this
    vulnerability is to data confidentiality and integrity as well as system availability. (CVE-2020-36328)

  - A flaw was found in libwebp in versions before 1.0.1. A use-after-free was found due to a thread being
    killed too early. The highest threat from this vulnerability is to data confidentiality and integrity as
    well as system availability. (CVE-2020-36329)

  - A flaw was found in libwebp in versions before 1.0.1. An out-of-bounds read was found in function
    ChunkAssignData. The highest threat from this vulnerability is to data confidentiality and to the service
    availability. (CVE-2020-36331)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2859
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31ba6ee0");
  script_set_attribute(attribute:"solution", value:
"Update the affected libwebp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-36329");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libwebp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.2.6");
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
if (uvp != "3.0.2.6") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.2.6");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "libwebp-0.3.0-7.h2.eulerosv2r7"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwebp");
}
