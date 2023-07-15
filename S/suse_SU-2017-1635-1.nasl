#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1635-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100985);
  script_version("3.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/06");

  script_cve_id("CVE-2017-7508", "CVE-2017-7520", "CVE-2017-7521");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : openvpn (SUSE-SU-2017:1635-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for openvpn fixes the following issues :

  - Some parts of the certificate-parsing code did not
    always clear all allocated memory. This would have
    allowed clients to leak a few bytes of memory for each
    connection attempt, thereby facilitating a (quite
    inefficient) DoS attack on the server. [bsc#1044947,
    CVE-2017-7521]

  - The ASN1 parsing code contained a bug that could have
    resulted in some buffers being free()d twice, and this
    issue could have potentially been triggered remotely by
    a VPN peer. [bsc#1044947, CVE-2017-7521]

  - If clients used a HTTP proxy with NTLM authentication, a
    man-in-the-middle attacker between client and proxy
    could cause the client to crash or disclose at most 96
    bytes of stack memory. The disclosed stack memory was
    likely to contain the proxy password. If the proxy
    password had not been reused, this was unlikely to
    compromise the security of the OpenVPN tunnel itself.
    Clients who did not use the

    --http-proxy option with ntlm2 authentication were not
    affected. [bsc#1044947, CVE-2017-7520]

  - It was possible to trigger an assertion by sending a
    malformed IPv6 packet. That issue could have been abused
    to remotely shutdown an openvpn server or client, if
    IPv6 and --mssfix were enabled and if the IPv6 networks
    used inside the VPN were known. [bsc#1044947,
    CVE-2017-7508]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1044947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7508/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7520/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-7521/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171635-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abcde14b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 6:zypper in -t patch
SUSE-OpenStack-Cloud-6-2017-1011=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2017-1011=1

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-1011=1

SUSE Linux Enterprise Server for Raspberry Pi 12-SP2:zypper in -t
patch SUSE-SLE-RPI-12-SP2-2017-1011=1

SUSE Linux Enterprise Server 12-SP2:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2017-1011=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2017-1011=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-1011=1

SUSE Linux Enterprise Desktop 12-SP2:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP2-2017-1011=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-auth-pam-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-auth-pam-plugin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/06/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0|1|2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0/1/2", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"1", reference:"openvpn-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openvpn-auth-pam-plugin-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openvpn-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"1", reference:"openvpn-debugsource-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openvpn-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openvpn-auth-pam-plugin-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openvpn-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"openvpn-debugsource-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvpn-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvpn-auth-pam-plugin-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvpn-auth-pam-plugin-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvpn-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"openvpn-debugsource-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openvpn-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openvpn-debuginfo-2.3.8-16.17.1")) flag++;
if (rpm_check(release:"SLED12", sp:"2", cpu:"x86_64", reference:"openvpn-debugsource-2.3.8-16.17.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openvpn");
}
