#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2023:0025-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(170267);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/16");

  script_cve_id("CVE-2022-46169");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/09");

  script_name(english:"openSUSE 15 Security Update : cacti, cacti-spine (openSUSE-SU-2023:0025-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2023:0025-1 advisory.

  - Cacti is an open source platform which provides a robust and extensible operational monitoring and fault
    management framework for users. In affected versions a command injection vulnerability allows an
    unauthenticated user to execute arbitrary code on a server running Cacti, if a specific data source was
    selected for any monitored device. The vulnerability resides in the `remote_agent.php` file. This file can
    be accessed without authentication. This function retrieves the IP address of the client via
    `get_client_addr` and resolves this IP address to the corresponding hostname via `gethostbyaddr`. After
    this, it is verified that an entry within the `poller` table exists, where the hostname corresponds to the
    resolved hostname. If such an entry was found, the function returns `true` and the client is authorized.
    This authorization can be bypassed due to the implementation of the `get_client_addr` function. The
    function is defined in the file `lib/functions.php` and checks serval `$_SERVER` variables to determine
    the IP address of the client. The variables beginning with `HTTP_` can be arbitrarily set by an attacker.
    Since there is a default entry in the `poller` table with the hostname of the server running Cacti, an
    attacker can bypass the authentication e.g. by providing the header `Forwarded-For: <TARGETIP>`. This way
    the function `get_client_addr` returns the IP address of the server running Cacti. The following call to
    `gethostbyaddr` will resolve this IP address to the hostname of the server, which will pass the `poller`
    hostname check because of the default entry. After the authorization of the `remote_agent.php` file is
    bypassed, an attacker can trigger different actions. One of these actions is called `polldata`. The called
    function `poll_for_data` retrieves a few request parameters and loads the corresponding `poller_item`
    entries from the database. If the `action` of a `poller_item` equals `POLLER_ACTION_SCRIPT_PHP`, the
    function `proc_open` is used to execute a PHP script. The attacker-controlled parameter `$poller_id` is
    retrieved via the function `get_nfilter_request_var`, which allows arbitrary strings. This variable is
    later inserted into the string passed to `proc_open`, which leads to a command injection vulnerability. By
    e.g. providing the `poller_id=;id` the `id` command is executed. In order to reach the vulnerable call,
    the attacker must provide a `host_id` and `local_data_id`, where the `action` of the corresponding
    `poller_item` is set to `POLLER_ACTION_SCRIPT_PHP`. Both of these ids (`host_id` and `local_data_id`) can
    easily be bruteforced. The only requirement is that a `poller_item` with an `POLLER_ACTION_SCRIPT_PHP`
    action exists. This is very likely on a productive instance because this action is added by some
    predefined templates like `Device - Uptime` or `Device - Polling Time`. This command injection
    vulnerability allows an unauthenticated user to execute arbitrary commands if a `poller_item` with the
    `action` type `POLLER_ACTION_SCRIPT_PHP` (`2`) is configured. The authorization bypass should be prevented
    by not allowing an attacker to make `get_client_addr` (file `lib/functions.php`) return an arbitrary IP
    address. This could be done by not honoring the `HTTP_...` `$_SERVER` variables. If these should be kept
    for compatibility reasons it should at least be prevented to fake the IP address of the server running
    Cacti. This vulnerability has been addressed in both the 1.2.x and 1.3.x release branches with `1.2.23`
    being the first release containing the patch. (CVE-2022-46169)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206185");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OAXXYXB4QU5PUFQHCVOLYJEKQJ6VSV45/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c6fda9ab");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-46169");
  script_set_attribute(attribute:"solution", value:
"Update the affected cacti and / or cacti-spine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-46169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Cacti 1.2.22 unauthenticated command injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:cacti-spine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.4");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.4)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.4', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'cacti-1.2.23-bp154.2.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'cacti-spine-1.2.23-bp154.2.6.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cacti / cacti-spine');
}
