#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2022:1271-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170223);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/08");

  script_cve_id(
    "CVE-2021-21290",
    "CVE-2021-21295",
    "CVE-2021-37136",
    "CVE-2021-37137",
    "CVE-2021-43797"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2022:1271-1");

  script_name(english:"openSUSE 15 Security Update : netty (SUSE-SU-2022:1271-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as referenced in the
SUSE-SU-2022:1271-1 advisory.

  - Netty is an open-source, asynchronous event-driven network application framework for rapid development of
    maintainable high performance protocol servers & clients. In Netty before version 4.1.59.Final there is a
    vulnerability on Unix-like systems involving an insecure temp file. When netty's multipart decoders are
    used local information disclosure can occur via the local system temporary directory if temporary storing
    uploads on the disk is enabled. On unix-like systems, the temporary directory is shared between all user.
    As such, writing to this directory using APIs that do not explicitly set the file/directory permissions
    can lead to information disclosure. Of note, this does not impact modern MacOS Operating Systems. The
    method File.createTempFile on unix-like systems creates a random file, but, by default will create this
    file with the permissions -rw-r--r--. Thus, if sensitive information is written to this file, other
    local users can read this information. This is the case in netty's AbstractDiskHttpData is vulnerable.
    This has been fixed in version 4.1.59.Final. As a workaround, one may specify your own java.io.tmpdir
    when you start the JVM or use DefaultHttpDataFactory.setBaseDir(...) to set the directory to something
    that is only readable by the current user. (CVE-2021-21290)

  - Netty is an open-source, asynchronous event-driven network application framework for rapid development of
    maintainable high performance protocol servers & clients. In Netty (io.netty:netty-codec-http2) before
    version 4.1.60.Final there is a vulnerability that enables request smuggling. If a Content-Length header
    is present in the original HTTP/2 request, the field is not validated by `Http2MultiplexHandler` as it is
    propagated up. This is fine as long as the request is not proxied through as HTTP/1.1. If the request
    comes in as an HTTP/2 stream, gets converted into the HTTP/1.1 domain objects (`HttpRequest`,
    `HttpContent`, etc.) via `Http2StreamFrameToHttpObjectCodec `and then sent up to the child channel's
    pipeline and proxied through a remote peer as HTTP/1.1 this may result in request smuggling. In a proxy
    case, users may assume the content-length is validated somehow, which is not the case. If the request is
    forwarded to a backend channel that is a HTTP/1.1 connection, the Content-Length now has meaning and needs
    to be checked. An attacker can smuggle requests inside the body as it gets downgraded from HTTP/2 to
    HTTP/1.1. For an example attack refer to the linked GitHub Advisory. Users are only affected if all of
    this is true: `HTTP2MultiplexCodec` or `Http2FrameCodec` is used, `Http2StreamFrameToHttpObjectCodec` is
    used to convert to HTTP/1.1 objects, and these HTTP/1.1 objects are forwarded to another remote peer. This
    has been patched in 4.1.60.Final As a workaround, the user can do the validation by themselves by
    implementing a custom `ChannelInboundHandler` that is put in the `ChannelPipeline` behind
    `Http2StreamFrameToHttpObjectCodec`. (CVE-2021-21295)

  - The Bzip2 decompression decoder function doesn't allow setting size restrictions on the decompressed
    output data (which affects the allocation size used during decompression). All users of Bzip2Decoder are
    affected. The malicious input can trigger an OOME and so a DoS attack (CVE-2021-37136)

  - The Snappy frame decoder function doesn't restrict the chunk length which may lead to excessive memory
    usage. Beside this it also may buffer reserved skippable chunks until the whole chunk was received which
    may lead to excessive memory usage as well. This vulnerability can be triggered by supplying malicious
    input that decompresses to a very big size (via a network stream or a file) or by sending a huge skippable
    chunk. (CVE-2021-37137)

  - Netty is an asynchronous event-driven network application framework for rapid development of maintainable
    high performance protocol servers & clients. Netty prior to version 4.1.71.Final skips control chars when
    they are present at the beginning / end of the header name. It should instead fail fast as these are not
    allowed by the spec and could lead to HTTP request smuggling. Failing to do the validation might cause
    netty to sanitize header names before it forward these to another remote system when used as proxy. This
    remote system can't see the invalid usage anymore, and therefore does not do the validation itself. Users
    should upgrade to version 4.1.71.Final. (CVE-2021-43797)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1182103");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1183262");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1190613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193672");
  # https://lists.suse.com/pipermail/sle-security-updates/2022-April/010773.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64d6deeb");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21290");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-21295");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37136");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37137");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-43797");
  script_set_attribute(attribute:"solution", value:
"Update the affected netty, netty-javadoc and / or netty-poms packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43797");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^SUSE") audit(AUDIT_OS_NOT, "openSUSE");
var os_ver = pregmatch(pattern: "^(SUSE[\d.]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SUSE15\.3)$", string:os_ver)) audit(AUDIT_OS_NOT, 'openSUSE 15', 'openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE (' + os_ver + ')', cpu);

var pkgs = [
    {'reference':'netty-4.1.75-150200.4.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'netty-javadoc-4.1.75-150200.4.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']},
    {'reference':'netty-poms-4.1.75-150200.4.6.2', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'netty / netty-javadoc / netty-poms');
}
