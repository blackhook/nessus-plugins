#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:0334-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(122147);
  script_version("1.3");
  script_cvs_date("Date: 2020/02/12");

  script_cve_id("CVE-2018-16843", "CVE-2018-16844", "CVE-2018-16845");

  script_name(english:"SUSE SLES15 Security Update : nginx (SUSE-SU-2019:0334-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for nginx to version 1.14.2 fixes the following issues :

Security vulnerabilities addressed :

CVE-2018-16843 CVE-2018-16844: Fixed an issue whereby a client using
HTTP/2 might cause excessive memory consumption and CPU usage
(bsc#1115025 bsc#1115022).

CVE-2018-16845: Fixed an issue which might result in worker process
memory disclosure whne processing of a specially crafted mp4 file with
the ngx_http_mp4_module (bsc#1115015).

Other bug fixes and changes made: Fixed an issue with handling of
client addresses when using unix domain listen sockets to work with
datagrams on Linux.

The logging level of the 'http request', 'https proxy request',
'unsupported protocol', 'version too low', 'no suitable key share',
and 'no suitable signature algorithm' SSL errors has been lowered from
'crit' to 'info'.

Fixed an issue with using OpenSSL 1.1.0 or newer it was not possible
to switch off 'ssl_prefer_server_ciphers' in a virtual server if it
was switched on in the default server.

Fixed an issue with TLS 1.3 always being enabled when built with
OpenSSL 1.1.0 and used with 1.1.1

Fixed an issue with sending a disk-buffered request body to a gRPC
backend

Fixed an issue with connections of some gRPC backends might not be
cached when using the 'keepalive' directive.

Fixed a segmentation fault, which might occur in a worker process if
the ngx_http_mp4_module was used on 32-bit platforms.

Fixed an issue, whereby working with gRPC backends might result in
excessive memory consumption.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1115025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16843/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16844/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-16845/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20190334-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b695a9d7"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2019-334=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-334=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16845");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nginx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nginx-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nginx-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/13");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019-2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", reference:"nginx-1.14.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nginx-debuginfo-1.14.2-3.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nginx-debugsource-1.14.2-3.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nginx");
}
