#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1396-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100407);
  script_version("3.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/03/30");

  script_cve_id("CVE-2017-7494");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/04/20");

  script_name(english:"SUSE SLES12 Security Update : samba (SUSE-SU-2017:1396-1) (SambaCry)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for samba fixes the following issue :

  - An unprivileged user with access to the samba server
    could cause smbd to load a specially crafted shared
    library, which then had the ability to execute arbitrary
    code on the server as 'root'. [CVE-2017-7494, bso#12780,
    bsc#1038231]

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1038231");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-7494/");
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171396-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?59620abd");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server for SAP 12:zypper in -t patch
SUSE-SLE-SAP-12-2017-852=1

SUSE Linux Enterprise Server 12-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-2017-852=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba is_known_pipename() Arbitrary Module Load');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgensec0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libregistry0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-raw0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"0", reference:"ctdb-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"ctdb-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libregistry0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libregistry0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-passdb0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-passdb0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debugsource-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-debuginfo-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc-binding0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libdcerpc0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libgensec0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-krb5pac0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-nbt0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr-standard0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libndr0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libnetapi0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-credentials0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-hostconfig0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-passdb0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-passdb0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamba-util0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsamdb0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient-raw0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbclient0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbconf0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libsmbldap0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libtevent-util0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"libwbclient0-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-client-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-libs-debuginfo-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-32bit-4.2.4-18.41.1")) flag++;
if (rpm_check(release:"SLES12", sp:"0", reference:"samba-winbind-debuginfo-32bit-4.2.4-18.41.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
