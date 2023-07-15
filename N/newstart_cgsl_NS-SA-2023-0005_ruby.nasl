#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2023-0005. The text
# itself is copyright (C) ZTE, Inc.
##

include('compat.inc');

if (description)
{
  script_id(171710);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/02/21");

  script_cve_id("CVE-2022-28739");

  script_name(english:"NewStart CGSL MAIN 6.02 : ruby Vulnerability (NS-SA-2023-0005)");

  script_set_attribute(attribute:"synopsis", value:
"The remote NewStart CGSL host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 6.02, has ruby packages installed that are affected by a
vulnerability:

  - There is a buffer over-read in Ruby before 2.6.10, 2.7.x before 2.7.6, 3.x before 3.0.4, and 3.1.x before
    3.1.2. It occurs in String-to-Float conversion, including Kernel#Float and String#to_f. (CVE-2022-28739)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2023-0005");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/info/CVE-2022-28739");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL ruby packages. Note that updated packages may not be available yet. Please contact ZTE for
more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-28739");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-bigdecimal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-io-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-psych");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:zte:cgsl_main:rubygems");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:zte:cgsl_main:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var os_release = get_kb_item('Host/ZTE-CGSL/release');
if (isnull(os_release) || os_release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, 'NewStart Carrier Grade Server Linux');

if (os_release !~ "CGSL MAIN 6.02")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 6.02');

if (!get_kb_item('Host/ZTE-CGSL/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'NewStart Carrier Grade Server Linux', cpu);

var flag = 0;

var pkgs = {
  'CGSL MAIN 6.02': [
    'ruby-2.6.10-109.module_el8.6.0+1154+d96790ac',
    'ruby-libs-2.6.10-109.module_el8.6.0+1154+d96790ac',
    'rubygem-bigdecimal-1.4.1-109.module_el8.6.0+1154+d96790ac',
    'rubygem-io-console-0.4.7-109.module_el8.6.0+1154+d96790ac',
    'rubygem-irb-1.0.0-109.module_el8.6.0+1154+d96790ac',
    'rubygem-json-2.1.0-109.module_el8.6.0+1154+d96790ac',
    'rubygem-openssl-2.1.2-109.module_el8.6.0+1154+d96790ac',
    'rubygem-psych-3.1.0-109.module_el8.6.0+1154+d96790ac',
    'rubygem-rdoc-6.1.2.1-109.module_el8.6.0+1154+d96790ac',
    'rubygems-3.0.3.1-109.module_el8.6.0+1154+d96790ac'
  ]
};
var pkg_list = pkgs[os_release];

foreach (pkg in pkg_list)
  if (rpm_check(release:'ZTE ' + os_release, reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ruby');
}
