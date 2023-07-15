#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(140894);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/12");

  script_cve_id(
    "CVE-2019-12519",
    "CVE-2019-12521",
    "CVE-2019-12528",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-8517",
    "CVE-2020-11945",
    "CVE-2020-24606"
  );

  script_name(english:"EulerOS 2.0 SP3 : squid (EulerOS-SA-2020-2127)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Squid before 4.13 and 5.x before 5.0.4 allows a trusted
    peer to perform Denial of Service by consuming all
    available CPU cycles during handling of a crafted Cache
    Digest response message. This only occurs when
    cache_peer is used with the cache digests feature. The
    problem exists because peerDigestHandleReply()
    livelocking in peer_digest.cc mishandles
    EOF.(CVE-2020-24606)

  - An issue was discovered in Squid through 4.7. When
    handling the tag esi:when when ESI is enabled, Squid
    calls ESIExpression::Evaluate. This function uses a
    fixed stack buffer to hold the expression while it's
    being evaluated. When processing the expression, it
    could either evaluate the top of the stack, or add a
    new member to the stack. When adding a new member,
    there is no check to ensure that the stack won't
    overflow.(CVE-2019-12519)

  - An issue was discovered in Squid through 4.7. When
    Squid is parsing ESI, it keeps the ESI elements in
    ESIContext. ESIContext contains a buffer for holding a
    stack of ESIElements. When a new ESIElement is parsed,
    it is added via addStackElement. addStackElement has a
    check for the number of elements in this buffer, but
    it's off by 1, leading to a Heap Overflow of 1 element.
    The overflow is within the same structure so it can't
    affect adjacent memory blocks, and thus just leads to a
    crash while processing.(CVE-2019-12521)

  - An issue was discovered in Squid before 5.0.2. A remote
    attacker can replay a sniffed Digest Authentication
    nonce to gain access to resources that are otherwise
    forbidden. This occurs because the attacker can
    overflow the nonce reference counter (a short integer).
    Remote code execution may occur if the pooled token
    credentials are freed (instead of replayed as valid
    credentials).(CVE-2020-11945)

  - An issue was discovered in Squid before 4.10. It allows
    a crafted FTP server to trigger disclosure of sensitive
    information from heap memory, such as information
    associated with other users' sessions or non-Squid
    processes.(CVE-2019-12528)

  - An issue was discovered in Squid before 4.10. Due to
    incorrect input validation, it can interpret crafted
    HTTP requests in unexpected ways to access server
    resources prohibited by earlier security
    filters.(CVE-2020-8449)

  - An issue was discovered in Squid before 4.10. Due to
    incorrect buffer management, a remote client can cause
    a buffer overflow in a Squid instance acting as a
    reverse proxy.(CVE-2020-8450)

  - An issue was discovered in Squid before 4.10. Due to
    incorrect input validation, the NTLM authentication
    credentials parser in ext_lm_group_acl may write to
    memory outside the credentials buffer. On systems with
    memory access protections, this can result in the
    helper process being terminated unexpectedly. This
    leads to the Squid process also terminating and a
    denial of service for all clients using the
    proxy.(CVE-2020-8517)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2127
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d82f7ecf");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-11945");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["squid-3.5.20-2.2.h8",
        "squid-migration-script-3.5.20-2.2.h8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
