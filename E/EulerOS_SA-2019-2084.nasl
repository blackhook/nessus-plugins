#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129443);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2018-16843",
    "CVE-2018-16844",
    "CVE-2019-9511",
    "CVE-2019-9513",
    "CVE-2019-9516"
  );
  script_xref(name:"CEA-ID", value:"CEA-2019-0643");

  script_name(english:"EulerOS 2.0 SP8 : nginx (EulerOS-SA-2019-2084)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the nginx packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - nginx before versions 1.15.6 and 1.14.1 has a
    vulnerability in the implementation of HTTP/2 that can
    allow for excessive memory consumption. This issue
    affects nginx compiled with the ngx_http_v2_module (not
    compiled by default) if the 'http2' option of the
    'listen' directive is used in a configuration
    file.(CVE-2018-16843)

  - nginx before versions 1.15.6 and 1.14.1 has a
    vulnerability in the implementation of HTTP/2 that can
    allow for excessive CPU usage. This issue affects nginx
    compiled with the ngx_http_v2_module (not compiled by
    default) if the 'http2' option of the 'listen'
    directive is used in a configuration
    file.(CVE-2018-16844)

  - Some HTTP/2 implementations are vulnerable to resource
    loops, potentially leading to a denial of service. The
    attacker creates multiple request streams and
    continually shuffles the priority of the streams in a
    way that causes substantial churn to the priority tree.
    This can consume excess CPU.(CVE-2019-9513)

  - Some HTTP/2 implementations are vulnerable to window
    size manipulation and stream prioritization
    manipulation, potentially leading to a denial of
    service. The attacker requests a large amount of data
    from a specified resource over multiple streams. They
    manipulate window size and stream priority to force the
    server to queue the data in 1-byte chunks. Depending on
    how efficiently this data is queued, this can consume
    excess CPU, memory, or both.(CVE-2019-9511)

  - Some HTTP/2 implementations are vulnerable to a header
    leak, potentially leading to a denial of service. The
    attacker sends a stream of headers with a 0-length
    header name and 0-length header value, optionally
    Huffman encoded into 1-byte or greater headers. Some
    implementations allocate memory for these headers and
    keep the allocation alive until the session dies. This
    can consume excess memory.(CVE-2019-9516)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2084
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b392da62");
  script_set_attribute(attribute:"solution", value:
"Update the affected nginx packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-all-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-http-image-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-http-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-http-xslt-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:nginx-mod-stream");
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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["nginx-1.12.1-14.h1.eulerosv2r8",
        "nginx-all-modules-1.12.1-14.h1.eulerosv2r8",
        "nginx-filesystem-1.12.1-14.h1.eulerosv2r8",
        "nginx-mod-http-image-filter-1.12.1-14.h1.eulerosv2r8",
        "nginx-mod-http-perl-1.12.1-14.h1.eulerosv2r8",
        "nginx-mod-http-xslt-filter-1.12.1-14.h1.eulerosv2r8",
        "nginx-mod-mail-1.12.1-14.h1.eulerosv2r8",
        "nginx-mod-stream-1.12.1-14.h1.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}
