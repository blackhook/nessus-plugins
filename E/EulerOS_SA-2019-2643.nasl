#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(132178);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2014-8176",
    "CVE-2015-4000",
    "CVE-2016-2181",
    "CVE-2016-2183"
  );
  script_bugtraq_id(74733, 75159);
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"EulerOS 2.0 SP3 : openssl098e (EulerOS-SA-2019-2643)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl098e package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - The Anti-Replay feature in the DTLS implementation in
    OpenSSL before 1.1.0 mishandles early use of a new
    epoch number in conjunction with a large sequence
    number, which allows remote attackers to cause a denial
    of service (false-positive packet drops) via spoofed
    DTLS records, related to rec_layer_d1.c and
    ssl3_record.c.(CVE-2016-2181)

  - The DES and Triple DES ciphers, as used in the TLS,
    SSH, and IPSec protocols and other protocols and
    products, have a birthday bound of approximately four
    billion blocks, which makes it easier for remote
    attackers to obtain cleartext data via a birthday
    attack against a long-duration encrypted session, as
    demonstrated by an HTTPS session using Triple DES in
    CBC mode, aka a 'Sweet32' attack.(CVE-2016-2183)

  - The dtls1_clear_queues function in ssl/d1_lib.c in
    OpenSSL before 0.9.8za, 1.0.0 before 1.0.0m, and 1.0.1
    before 1.0.1h frees data structures without considering
    that application data can arrive between a
    ChangeCipherSpec message and a Finished message, which
    allows remote DTLS peers to cause a denial of service
    (memory corruption and application crash) or possibly
    have unspecified other impact via unexpected
    application data.(CVE-2014-8176)

  - The TLS protocol 1.2 and earlier, when a DHE_EXPORT
    ciphersuite is enabled on a server but not on a client,
    does not properly convey a DHE_EXPORT choice, which
    allows man-in-the-middle attackers to conduct
    cipher-downgrade attacks by rewriting a ClientHello
    with DHE replaced by DHE_EXPORT and then rewriting a
    ServerHello with DHE_EXPORT replaced by DHE, aka the
    'Logjam' issue.(CVE-2015-4000)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2643
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eb44e4c7");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl098e packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8176");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2016-2183");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl098e");
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
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl098e-0.9.8e-29.3.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl098e");
}
