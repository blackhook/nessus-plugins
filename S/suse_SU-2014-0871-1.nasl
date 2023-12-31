#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2014:0871-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(83631);
  script_version("2.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2012-0862", "CVE-2013-4342");
  script_bugtraq_id(53720, 62871);

  script_name(english:"SUSE SLES10 / SLES11 Security Update : xinetd (SUSE-SU-2014:0871-1)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Xinetd receives a LTSS roll-up update to fix two security issues.

  - CVE-2012-0862: xinetd enabled all services when tcp
    multiplexing is used.

  - CVE-2013-4342: xinetd ignored user and group directives
    for tcpmux services, running services as root.

While both issues are not so problematic on their own, in combination
the impact is greater and enabling tcpmux would be risky.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  # http://download.suse.com/patch/finder/?keywords=02d02e7774b10b86c728bb88af735b33
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?abbe8ebf"
  );
  # http://download.suse.com/patch/finder/?keywords=5d400fd9a30cb44112b8a54c0743cc7b
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0560dd2a"
  );
  # http://download.suse.com/patch/finder/?keywords=697d9a5cda282587ef2ff61975bbcad4
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bcdd017c"
  );
  # http://download.suse.com/patch/finder/?keywords=c6f4a3dc598f45466f0a0699473c1f57
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?77c63c4b"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2012-0862.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2013-4342.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/762294"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/844230"
  );
  # https://www.suse.com/support/update/announcement/2014/suse-su-20140871-1.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3a24c40a"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11 SP2 LTSS :

zypper in -t patch slessp2-xinetd-9417

SUSE Linux Enterprise Server 11 SP1 LTSS :

zypper in -t patch slessp1-xinetd-9418

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:xinetd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:10");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/07/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLES10|SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES10 / SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! ereg(pattern:"^1|2$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP1/2", os_ver + " SP" + sp);
if (os_ver == "SLES10" && (! ereg(pattern:"^4|3$", string:sp))) audit(AUDIT_OS_NOT, "SLES10 SP4/3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"1", reference:"xinetd-2.3.14-130.133.1")) flag++;
if (rpm_check(release:"SLES11", sp:"2", reference:"xinetd-2.3.14-130.133.1")) flag++;
if (rpm_check(release:"SLES10", sp:"4", reference:"xinetd-2.3.14-14.12.1")) flag++;
if (rpm_check(release:"SLES10", sp:"3", reference:"xinetd-2.3.14-14.12.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xinetd");
}
