#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:1334-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153874);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/09");

  script_cve_id("CVE-2021-22116", "CVE-2021-32718", "CVE-2021-32719");
  script_xref(name:"IAVB", value:"2021-B-0029-S");
  script_xref(name:"IAVB", value:"2021-B-0043");

  script_name(english:"openSUSE 15 Security Update : rabbitmq-server (openSUSE-SU-2021:1334-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by multiple vulnerabilities as referenced in
the openSUSE-SU-2021:1334-1 advisory.

  - RabbitMQ is a multi-protocol messaging broker. In rabbitmq-server prior to version 3.8.18, when a
    federation link was displayed in the RabbitMQ management UI via the `rabbitmq_federation_management`
    plugin, its consumer tag was rendered without proper <script> tag sanitization. This potentially allows
    for JavaScript code execution in the context of the page. The user must be signed in and have elevated
    permissions (manage federation upstreams and policies) for this to occur. The vulnerability is patched in
    RabbitMQ 3.8.18. As a workaround, disable the `rabbitmq_federation_management` plugin and use [CLI
    tools](https://www.rabbitmq.com/cli.html) instead. (CVE-2021-32719)

  - RabbitMQ all versions prior to 3.8.16 are prone to a denial of service vulnerability due to improper input
    validation in AMQP 1.0 client connection endpoint. A malicious user can exploit the vulnerability by
    sending malicious AMQP messages to the target RabbitMQ instance having the AMQP 1.0 plugin enabled.
    (CVE-2021-22116)

  - RabbitMQ is a multi-protocol messaging broker. In rabbitmq-server prior to version 3.8.17, a new user
    being added via management UI could lead to the user's bane being rendered in a confirmation message
    without proper `<script>` tag sanitization, potentially allowing for JavaScript code execution in the
    context of the page. In order for this to occur, the user must be signed in and have elevated permissions
    (other user management). The vulnerability is patched in RabbitMQ 3.8.17. As a workaround, disable
    `rabbitmq_management` plugin and use CLI tools for management operations and Prometheus and Grafana for
    metrics and monitoring. (CVE-2021-32718)

In rabbitmq-server prior to version 3.8.17, a new user being added via management UI could lead to the user's bane being
rendered in a confirmation message without proper `");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1185075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1186203");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187818");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1187819");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/FWIIK75CV5Y6TWUXN67IYXFNHIHRZSXN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5086900e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-22116");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32718");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-32719");
  script_set_attribute(attribute:"solution", value:
"Update the affected erlang-rabbitmq-client, rabbitmq-server and / or rabbitmq-server-plugins packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-32719");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-32718");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:erlang-rabbitmq-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rabbitmq-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rabbitmq-server-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.2', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'erlang-rabbitmq-client-3.8.3-lp152.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rabbitmq-server-3.8.3-lp152.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'rabbitmq-server-plugins-3.8.3-lp152.2.3.1', 'cpu':'x86_64', 'release':'SUSE15.2', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'erlang-rabbitmq-client / rabbitmq-server / rabbitmq-server-plugins');
}
