#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2017:1581-1.
# The text itself is copyright (C) SUSE.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(100907);
  script_version("3.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2017-5200", "CVE-2017-8109");

  script_name(english:"SUSE SLES11 Security Update : Salt (SUSE-SU-2017:1581-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for salt provides version 2016.11.4 and brings various
fixes and improvements :

  - Adding a salt-minion watchdog for RHEL6 and SLES11
    systems (sysV) to restart salt-minion in case of crashes
    during upgrade.

  - Fix format error. (bsc#1043111)

  - Fix ownership for whole master cache directory.
    (bsc#1035914)

  - Disable 3rd party runtime packages to be explicitly
    recommended. (bsc#1040886)

  - Fix insecure permissions in salt-ssh temporary files.
    (bsc#1035912, CVE-2017-8109)

  - Disable custom rosters for Salt SSH via Salt API.
    (bsc#1011800, CVE-2017-5200)

  - Orchestrate and batches don't return false failed
    information anymore.

  - Speed-up cherrypy by removing sleep call.

  - Fix os_family grains on SUSE. (bsc#1038855)

  - Fix setting the language on SUSE systems. (bsc#1038855)

  - Use SUSE specific salt-api.service. (bsc#1039370)

  - Fix using hostname for minion ID as '127'.

  - Fix core grains constants for timezone. (bsc#1032931)

  - Minor fixes on new pkg.list_downloaded.

  - Listing all type of advisory patches for Yum module.

  - Prevents zero length error on Python 2.6.

  - Fixes zypper test error after backporting.

  - Raet protocol is no longer supported. (bsc#1020831)

  - Fix moving SSH data to the new home. (bsc#1027722)

  - Fix logrotating /var/log/salt/minion. (bsc#1030009)

  - Fix result of master_tops extension is mutually
    overwritten. (bsc#1030073)

  - Allows to set 'timeout' and 'gather_job_timeout' via
    kwargs.

  - Allows to set custom timeouts for 'manage.up' and
    'manage.status'.

  - Use salt's ordereddict for comparison.

  - Fix scripts for salt-proxy.

  - Add openscap module.

  - File.get_managed regression fix.

  - Fix translate variable arguments if they contain hidden
    keywords. (bsc#1025896)

  - Added unit test for dockerng.sls_build dryrun.

  - Added dryrun to dockerng.sls_build.

  - Update dockerng minimal version requirements.

  - Fix format error in error parsing.

  - Keep fix for migrating salt home directory.
    (bsc#1022562)

  - Fix salt pkg.latest raises exception if package is not
    available. (bsc#1012999)

  - Timezone should always be in UTC. (bsc#1017078)

  - Fix timezone handling for rpm installtime. (bsc#1017078)

  - Increasing timeouts for running integrations tests.

  - Add buildargs option to dockerng.build module.

  - Fix error when missing ssh-option parameter.

  - Re-add yum notify plugin.

  - All kwargs to dockerng.create to provide all features to
    sls_build as well.

  - Datetime should be returned always in UTC.

  - Fix possible crash while deserialising data on infinite
    recursion in scheduled state. (bsc#1036125)

  - Documentation refresh to 2016.11.4

  - For a detailed description, please refer to :

  +
    https://docs.saltstack.com/en/develop/topics/releases/20
    16.11.4.html

  +
    https://docs.saltstack.com/en/develop/topics/releases/20
    16.11.3.html

  +
    https://docs.saltstack.com/en/develop/topics/releases/20
    16.11.2.html

  +
    https://docs.saltstack.com/en/develop/topics/releases/20
    16.11.1.html

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1011800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1012999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1017078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1020831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1022562"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1025896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1027722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1030073"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1032931"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1035914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1036125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1038855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1039370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1040886"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1043111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.1.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.2.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.3.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://docs.saltstack.com/en/develop/topics/releases/2016.11.4.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-5200/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2017-8109/"
  );
  # https://www.suse.com/support/update/announcement/2017/suse-su-20171581-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?632f8742"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Server 11-SP4-CLIENT-TOOLS:zypper in -t patch
slesctsp4-salt-201705-13150=1

SUSE Linux Enterprise Server 11-SP3-CLIENT-TOOLS:zypper in -t patch
slesctsp3-salt-201705-13150=1

To bring your system up-to-date, use 'zypper patch'."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:11");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/06/20");
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
if (! preg(pattern:"^(SLES11)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES11", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES11" && (! preg(pattern:"^(3|4)$", string:sp))) audit(AUDIT_OS_NOT, "SLES11 SP3/4", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES11", sp:"4", reference:"salt-2016.11.4-42.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"salt-doc-2016.11.4-42.2")) flag++;
if (rpm_check(release:"SLES11", sp:"4", reference:"salt-minion-2016.11.4-42.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"salt-2016.11.4-42.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"salt-doc-2016.11.4-42.2")) flag++;
if (rpm_check(release:"SLES11", sp:"3", reference:"salt-minion-2016.11.4-42.2")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Salt");
}
