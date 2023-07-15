#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-195.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(122295);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845");

  script_name(english:"openSUSE Security Update : nginx (openSUSE-2019-195)");
  script_summary(english:"Check for the openSUSE-2019-195 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for nginx fixes the following issues :

nginx was updated to 1.14.2 :

  - Bugfix: nginx could not be built on Fedora 28 Linux.

  - Bugfix: in handling of client addresses when using unix
    domain listen sockets to work with datagrams on Linux.

  - Change: the logging level of the 'http request', 'https
    proxy request', 'unsupported protocol', 'version too
    low', 'no suitable key share', and 'no suitable
    signature algorithm' SSL errors has been lowered from
    'crit' to 'info'.

  - Bugfix: when using OpenSSL 1.1.0 or newer it was not
    possible to switch off 'ssl_prefer_server_ciphers' in a
    virtual server if it was switched on in the default
    server.

  - Bugfix: nginx could not be built with LibreSSL 2.8.0.

  - Bugfix: if nginx was built with OpenSSL 1.1.0 and used
    with OpenSSL 1.1.1, the TLS 1.3 protocol was always
    enabled.

  - Bugfix: sending a disk-buffered request body to a gRPC
    backend might fail.

  - Bugfix: connections with some gRPC backends might not be
    cached when using the 'keepalive' directive.

  - Bugfix: a segmentation fault might occur in a worker
    process if the ngx_http_mp4_module was used on 32-bit
    platforms.

Changes with nginx 1.14.1 :

  - Security: when using HTTP/2 a client might cause
    excessive memory consumption (CVE-2018-16843) and CPU
    usage (CVE-2018-16844).

  - Security: processing of a specially crafted mp4 file
    with the ngx_http_mp4_module might result in worker
    process memory disclosure (CVE-2018-16845).

  - Bugfix: working with gRPC backends might result in
    excessive memory consumption.

Changes with nginx 1.13.12 :

  - Bugfix: connections with gRPC backends might be closed
    unexpectedly when returning a large response.

Changes with nginx 1.13.10

  - Feature: the 'set' parameter of the 'include' SSI
    directive now allows writing arbitrary responses to a
    variable; the 'subrequest_output_buffer_size' directive
    defines maximum response size.

  - Feature: now nginx uses clock_gettime(CLOCK_MONOTONIC)
    if available, to avoid timeouts being incorrectly
    triggered on system time changes.

  - Feature: the 'escape=none' parameter of the 'log_format'
    directive. Thanks to Johannes Baiter and Calin Don.

  - Feature: the $ssl_preread_alpn_protocols variable in the
    ngx_stream_ssl_preread_module.

  - Feature: the ngx_http_grpc_module.

  - Bugfix: in memory allocation error handling in the 'geo'
    directive.

  - Bugfix: when using variables in the
    'auth_basic_user_file' directive a null character might
    appear in logs. Thanks to Vadim Filimonov."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1115025"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected nginx packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16845");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:nginx-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:vim-plugin-nginx");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"nginx-1.14.2-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nginx-debuginfo-1.14.2-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"nginx-debugsource-1.14.2-lp150.2.4.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"vim-plugin-nginx-1.14.2-lp150.2.4.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx / nginx-debuginfo / nginx-debugsource / vim-plugin-nginx");
}
