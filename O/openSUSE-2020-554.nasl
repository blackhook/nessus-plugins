#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-554.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(136011);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/03/09");

  script_cve_id("CVE-2016-5195", "CVE-2016-8859", "CVE-2017-1002101", "CVE-2018-1002105", "CVE-2018-16873", "CVE-2018-16874", "CVE-2019-10214");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"openSUSE Security Update : kubernetes (openSUSE-2020-554) (Dirty COW)");
  script_summary(english:"Check for the openSUSE-2020-554 patch");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update introduces kubernetes version 1.14.1 and cri-o 1.17.1 to
Leap 15.1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1039663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042383"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1042387"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1057277"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1059207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1061027"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1065972"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1069469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084766"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1085009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086185"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1086412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095131"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1095154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096773"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1097473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1100838"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1101010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1104821"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112980"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118897"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1118898"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136403"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1144065"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1155323"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161056"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1161179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/325820"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://features.opensuse.org/326485"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Update the affected kubernetes packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1002105");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cri-o-kubeadm-criconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cri-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.14");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:go1.14-race");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-apiserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-controller-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-kubeadm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-kubelet-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-kubelet1.17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-kubelet1.18");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kubernetes-scheduler");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"cri-o-1.17.1-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cri-o-kubeadm-criconfig-1.17.1-lp151.2.2") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"cri-tools-1.18.0-lp151.2.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"go1.14-1.14-lp151.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"go1.14-race-1.14-lp151.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-apiserver-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-client-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-controller-manager-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-kubeadm-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-kubelet-common-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-kubelet1.17-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-kubelet1.18-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-master-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-node-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-proxy-1.18.0-lp151.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kubernetes-scheduler-1.18.0-lp151.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "cri-o / cri-o-kubeadm-criconfig / cri-tools / go1.14 / go1.14-race / etc");
}
