#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(169809);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/01/10");

  script_cve_id(
    "CVE-2021-25214",
    "CVE-2021-25215",
    "CVE-2021-25219",
    "CVE-2021-25220",
    "CVE-2022-2928",
    "CVE-2022-2929"
  );
  script_xref(name:"IAVB", value:"2022-B-0037");

  script_name(english:"EulerOS Virtualization 2.10.0 : dhcp (EulerOS-SA-2023-1165)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the dhcp package installed, the EulerOS Virtualization installation on the remote host is
affected by the following vulnerabilities :

  - In BIND 9.8.5 -> 9.8.8, 9.9.3 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and
    9.16.8-S1 -> 9.16.13-S1 of BIND 9 Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11
    of the BIND 9.17 development branch, when a vulnerable version of named receives a malformed IXFR
    triggering the flaw described above, the named process will terminate due to a failed assertion the next
    time the transferred secondary zone is refreshed. (CVE-2021-25214)

  - In BIND 9.0.0 -> 9.11.29, 9.12.0 -> 9.16.13, and versions BIND 9.9.3-S1 -> 9.11.29-S1 and 9.16.8-S1 ->
    9.16.13-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.11 of the BIND
    9.17 development branch, when a vulnerable version of named receives a query for a record triggering the
    flaw described above, the named process will terminate due to a failed assertion check. The vulnerability
    affects all currently maintained BIND 9 branches (9.11, 9.11-S, 9.16, 9.16-S, 9.17) as well as all other
    versions of BIND 9. (CVE-2021-25215)

  - In BIND 9.3.0 -> 9.11.35, 9.12.0 -> 9.16.21, and versions 9.9.3-S1 -> 9.11.35-S1 and 9.16.8-S1 ->
    9.16.21-S1 of BIND Supported Preview Edition, as well as release versions 9.17.0 -> 9.17.18 of the BIND
    9.17 development branch, exploitation of broken authoritative servers using a flaw in response processing
    can cause degradation in BIND resolver performance. The way the lame cache is currently designed makes it
    possible for its internal data structures to grow almost infinitely, which may cause significant delays in
    client query processing. (CVE-2021-25219)

  - BIND 9.11.0 -> 9.11.36 9.12.0 -> 9.16.26 9.17.0 -> 9.18.0 BIND Supported Preview Editions: 9.11.4-S1 ->
    9.11.36-S1 9.16.8-S1 -> 9.16.26-S1 Versions of BIND 9 earlier than those shown - back to 9.1.0, including
    Supported Preview Editions - are also believed to be affected but have not been tested as they are EOL.
    The cache could become poisoned with incorrect records leading to queries being made to the wrong servers,
    which might also result in false information being returned to clients. (CVE-2021-25220)

  - In ISC DHCP 4.4.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1, when the function
    option_code_hash_lookup() is called from add_option(), it increases the option's refcount field. However,
    there is not a corresponding call to option_dereference() to decrement the refcount field. The function
    add_option() is only used in server responses to lease query packets. Each lease query response calls this
    function for several options, so eventually, the reference counters could overflow and cause the server to
    abort. (CVE-2022-2928)

  - In ISC DHCP 1.0 -> 4.4.3, ISC DHCP 4.1-ESV-R1 -> 4.1-ESV-R16-P1 a system with access to a DHCP server,
    sending DHCP packets crafted to include fqdn labels longer than 63 bytes, could eventually cause the
    server to run out of memory. (CVE-2022-2929)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-1165
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?29d060c9");
  script_set_attribute(attribute:"solution", value:
"Update the affected dhcp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25220");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.10.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.10.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "dhcp-4.4.2-3.h16.eulerosv2r10"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "dhcp");
}
