#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0631-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(146885);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/11/09");

  script_cve_id(
    "CVE-2020-28243",
    "CVE-2020-28972",
    "CVE-2020-35662",
    "CVE-2021-25281",
    "CVE-2021-25282",
    "CVE-2021-25283",
    "CVE-2021-25284",
    "CVE-2021-3144",
    "CVE-2021-3148",
    "CVE-2021-3197"
  );
  script_xref(name:"IAVA", value:"2021-A-0112-S");

  script_name(english:"SUSE SLES15 Security Update : salt (SUSE-SU-2021:0631-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for salt fixes the following issues :

Fix regression on cmd.run when passing tuples as cmd (bsc#1182740)

Allow extra_filerefs as sanitized kwargs for SSH client

Fix errors with virt.update

Fix for multiple for security issues (CVE-2020-28243) (CVE-2020-28972)
(CVE-2020-35662) (CVE-2021-3148) (CVE-2021-3144) (CVE-2021-25281)
(CVE-2021-25282) (CVE-2021-25283) (CVE-2021-25284) (CVE-2021-3197)
(bsc#1181550) (bsc#1181556) (bsc#1181557) (bsc#1181558) (bsc#1181559)
(bsc#1181560) (bsc#1181561) (bsc#1181562) (bsc#1181563) (bsc#1181564)
(bsc#1181565)

virt: search for grub.xen path

Xen spicevmc, DNS SRV records backports: Fix virtual network generated
DNS XML for SRV records Don't add spicevmc channel to xen VMs

virt UEFI fix: virt.update when efi=True

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181550");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181556");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181558");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181560");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181561");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181562");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181563");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181564");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1181565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1182740");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28243/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-28972/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-35662/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25281/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25282/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25283/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-25284/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3144/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3148/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-3197/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210631-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f1c875ed");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Manager Server 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Server-4.0-2021-631=1

SUSE Manager Retail Branch Server 4.0 :

zypper in -t patch
SUSE-SLE-Product-SUSE-Manager-Retail-Branch-Server-4.0-2021-631=1

SUSE Manager Proxy 4.0 :

zypper in -t patch SUSE-SLE-Product-SUSE-Manager-Proxy-4.0-2021-631=1

SUSE Linux Enterprise Server for SAP 15-SP1 :

zypper in -t patch SUSE-SLE-Product-SLES_SAP-15-SP1-2021-631=1

SUSE Linux Enterprise Server 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-LTSS-2021-631=1

SUSE Linux Enterprise Server 15-SP1-BCL :

zypper in -t patch SUSE-SLE-Product-SLES-15-SP1-BCL-2021-631=1

SUSE Linux Enterprise High Performance Computing 15-SP1-LTSS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-LTSS-2021-631=1

SUSE Linux Enterprise High Performance Computing 15-SP1-ESPOS :

zypper in -t patch SUSE-SLE-Product-HPC-15-SP1-ESPOS-2021-631=1

SUSE Enterprise Storage 6 :

zypper in -t patch SUSE-Storage-6-2021-631=1

SUSE CaaS Platform 4.0 :

To install this update, use the SUSE CaaS Platform 'skuba' tool. I
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt API Unauthenticated RCE through wheel_async client');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python2-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-standalone-formulas-configuration");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"python2-salt-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"python3-salt-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-api-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-cloud-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-doc-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-master-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-minion-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-proxy-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-ssh-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-standalone-formulas-configuration-3000-24.1")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"salt-syndic-3000-24.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "salt");
}
