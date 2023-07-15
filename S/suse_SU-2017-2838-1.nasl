#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:2838-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(104141);
  script_version("3.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id(
    "CVE-2016-6329",
    "CVE-2017-12166",
    "CVE-2017-7478",
    "CVE-2017-7479"
  );
  script_xref(name:"IAVA", value:"2017-A-0285");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SUSE SLES11 Security Update : openvpn (SUSE-SU-2017:2838-1) (SWEET32)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for openvpn fixes the following security issues :

  - CVE-2017-12166: OpenVPN was vulnerable to a buffer
    overflow vulnerability when key-method 1 is used,
    possibly resulting in code execution. (bsc#1060877).

  - CVE-2016-6329: Now show which ciphers should no longer
    be used in openvpn --show-ciphers to avoid the SWEET32
    attack (bsc#995374)

  - CVE-2017-7478: OpenVPN was vulnerable to unauthenticated
    Denial of Service of server via received large control
    packet. (bsc#1038709)

  - CVE-2017-7479: OpenVPN was vulnerable to reachable
    assertion when packet-ID counter rolls over resulting
    into Denial of Service of server by authenticated
    attacker. (bsc#1038711)

  - Some other hardening fixes have also been applied
    (bsc#1038713)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1038709");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1038711");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1038713");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1060877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=995374");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2016-6329/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-12166/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7478/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7479/");
  # https://www.suse.com/support/update/announcement/2017/suse-su-20172838-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bcc068ba");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4:zypper in -t patch
slessp4-openvpn-13322=1

SUSE Linux Enterprise Server 11-SP3-LTSS:zypper in -t patch
slessp3-openvpn-13322=1

SUSE Linux Enterprise Point of Sale 11-SP3:zypper in -t patch
sleposp3-openvpn-13322=1

SUSE Linux Enterprise Debuginfo 11-SP4:zypper in -t patch
dbgsp4-openvpn-13322=1

SUSE Linux Enterprise Debuginfo 11-SP3:zypper in -t patch
dbgsp3-openvpn-13322=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:openvpn-auth-pam-plugin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"openvpn-2.0.9-143.47.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"openvpn-auth-pam-plugin-2.0.9-143.47.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openvpn-2.0.9-143.47.3.1")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"openvpn-auth-pam-plugin-2.0.9-143.47.3.1")) flag++;


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
