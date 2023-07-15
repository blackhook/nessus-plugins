#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-388.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(109293);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/19");

  script_cve_id("CVE-2016-9639", "CVE-2017-12791", "CVE-2017-14695", "CVE-2017-14696", "CVE-2017-5200");
  script_xref(name:"IAVB", value:"2017-B-0112-S");

  script_name(english:"openSUSE Security Update : salt (openSUSE-2018-388)");
  script_summary(english:"Check for the openSUSE-2018-388 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for salt fixes the following issues :

  - [Regression] Permission problem: salt-ssh minion
    boostrap doesn't work anymore. (bsc#1027722)

  - wrong use of os_family string for Suse in the locale
    module and others (bsc#1038855)

  - Cannot bootstrap a host using 'Manage system completely
    via SSH (will not install an agent)' (bsc#1002529)

  - add user to or replace members of group not working with
    SLES11 SPx (bsc#978150)

  - SLES-12-GA client fail to start salt minion (SUSE
    MANAGER 3.0) (bsc#991048)

  - salt pkg.latest raises exception if package is not
    availible (bsc#1012999)

  - pkg.list_products on 'registerrelease' and 'productline'
    returns boolean.False if empty (bsc#989193)

  - SLES-12-SP1 salt-minion clients has no Base Channel
    added by default (bsc#986019)

  - 'The system requires a reboot' does not disappear from
    web-UI despite the reboot (bsc#1017078)

  - Remove option -f from startproc (bsc#975733)

  - [PYTHON2] package salt-minion requires /usr/bin/python
    (bsc#1081592)

  - Upgrading packages on RHEL6/7 client fails (bsc#1068566)

  - /var/log/salt has insecure permissions (bsc#1071322)

  - [Minion-bootstrapping] Invalid char cause server
    (salt-master ERROR) (bsc#1011304)

  - CVE-2016-9639: Possible information leak due to revoked
    keys still being used (bsc#1012398)

  - Bootstrapping SLES12 minion invalid (bsc#1053376)

  - Minions not correctly onboarded if Proxy has multiple
    FQDNs (bsc#1063419)

  - salt --summary '*' <function> reporting '# of minions
    that did not return' wrongly (bsc#972311)

  - RH-L3 SALT - Stacktrace if nscd package is not present
    when using nscd state (bsc#1027044)

  - Inspector broken: no module 'query' or 'inspector' while
    querying or inspecting (bsc#989798)

  - [ Regression ]Centos7 Minion remote command execution
    from gui or cli , minion not responding (bsc#1027240)

  - SALT, minion_id generation doesn't match the newhostname
    (bsc#967803)

  - Salt API server shuts down when SSH call with no matches
    is issued (bsc#1004723)

  - /var/log/salt/minion fails logrotate (bsc#1030009)

  - Salt proxy test.ping crashes (bsc#975303)

  - salt master flood log with useless messages (bsc#985661)

  - After bootstrap salt client has deprecation warnings
    (bsc#1041993)

  - Head: salt 2017.7.2 starts salt-master as user root
    (bsc#1064520)

  - CVE-2017-12791: Maliciously crafted minion IDs can cause
    unwanted directory traversals on the Salt-master
    (bsc#1053955)

  - salt-2017.7.2 - broken %post script for salt-master
    (bsc#1079048)

  - Tearing down deployment with SaltStack Kubernetes module
    always shows error (bsc#1059291)

  - lvm.vg_present does not recognize PV with certain LVM
    filter settings. (bsc#988506)

  - High state fails: No service execution module loaded:
    check support for service (bsc#1065792)

  - When multiple versions of a package are installed on a
    minion, patch status may vary (bsc#972490)

  - Salt cp.push does not work on SUMA 3.2 Builds because of
    python3.4 (bsc#1075950)

  - timezone modue does not update /etc/sysconfig/clock
    (bsc#1008933)

  - Add patches to salt to support SUSE Manager scalability
    features (bsc#1052264)

  - salt-minion failed to start on minimal RHEL6 because of
    DBus exception during load of snapper module
    (bsc#993039)

  - Permission denied: '/var/run/salt-master.pid'
    (bsc#1050003)

  - Jobs scheduled to run at a future time stay pending for
    Salt minions (bsc#1036125)

  - Backport kubernetes-modules to salt (bsc#1051948)

  - After highstate: The minion function caused an exception
    (bsc#1068446)

  - VUL-0: CVE-2017-14695: salt: directory traversal
    vulnerability in minion id validation (bsc#1062462)

  - unable to update salt-minion on RHEL (bsc#1022841)

  - Nodes run out of memory due to salt-minion process
    (bsc#983512)

  - [Proxy] 'Broken pipe' during bootstrap of salt minion
    (bsc#1039370)

  - incorrect return code from /etc/rc.d/salt-minion
    (bsc#999852)

  - CVE-2017-5200: Salt-ssh via api let's run arbitrary
    commands as user salt (bsc#1011800)

  - beacons.conf on salt-minion not processed (bsc#1060230)

  - SLES11 SP3 salt-minion Client Cannot Select Base Channel
    (bsc#975093)

  - salt-ssh sys.doc gives authentication failure without
    arguments (bsc#1019386)

  - minion bootstrapping: error when bootstrap SLE11 clients
    (bsc#990439)

  - Certificate Deployment Fails for SLES11 SP3 Clients
    (bsc#975757)

  - state.module run() does not translate varargs
    (bsc#1025896)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1002529"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1004723"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1008933"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011304"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1011800"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012398"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1012999"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1017078"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1019386"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1022841"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1025896"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027044"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1027722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1030009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1036125"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1038855"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039370"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1041993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1050003"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1051948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1052264"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1053955"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059291"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1060230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1062462"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1063419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1064520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068446"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1068566"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1071322"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1075950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1079048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1081592"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=967803"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972311"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=972490"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975093"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975733"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=975757"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=978150"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=983512"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=985661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=986019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=988506"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989193"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=989798"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=990439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=991048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=993039"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=999852"
  );
  # https://features.opensuse.org/320559
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected salt packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python2-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:salt-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/24");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2018-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"python2-salt-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-salt-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-api-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-bash-completion-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-cloud-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-fish-completion-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-master-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-minion-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-proxy-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-ssh-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-syndic-2018.3.0-17.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"salt-zsh-completion-2018.3.0-17.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python2-salt / python3-salt / salt / salt-api / etc");
}
