#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1604.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(141167);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/10/21");

  script_cve_id("CVE-2020-11800", "CVE-2020-15803");

  script_name(english:"openSUSE Security Update : zabbix (openSUSE-2020-1604)");
  script_summary(english:"Check for the openSUSE-2020-1604 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for zabbix fixes the following issues :

Updated to version 3.0.31.

  + CVE-2020-15803: Fixed an XSS in the URL Widget
    (boo#1174253)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174253"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected zabbix packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11800");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-java-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-phpfrontend");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-proxy-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-mysql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-sqlite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:zabbix-server-sqlite-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/07/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/05");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1|SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1 / 15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"zabbix-agent-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-agent-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-bash-completion-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-debugsource-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-java-gateway-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-phpfrontend-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-mysql-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-mysql-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-postgresql-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-postgresql-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-sqlite-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-proxy-sqlite-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-mysql-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-mysql-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-postgresql-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-postgresql-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-sqlite-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"zabbix-server-sqlite-debuginfo-3.0.31-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-agent-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-agent-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-bash-completion-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-debugsource-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-java-gateway-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-phpfrontend-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-mysql-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-mysql-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-postgresql-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-postgresql-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-sqlite-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-proxy-sqlite-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-mysql-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-mysql-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-postgresql-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-postgresql-debuginfo-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-sqlite-3.0.31-lp152.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"zabbix-server-sqlite-debuginfo-3.0.31-lp152.2.3.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "zabbix-agent / zabbix-agent-debuginfo / zabbix-bash-completion / etc");
}
