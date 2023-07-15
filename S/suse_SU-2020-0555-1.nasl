#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:0555-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(134285);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/16");

  script_cve_id("CVE-2018-18074");

  script_name(english:"SUSE SLES12 Security Update : python-aws-sam-translator, python-boto3, python-botocore, python-cfn-lint, python-jsonschema, python-nose2, python-parameterized, python-pathlib2, python-pytest-cov, python-requests, python-s3transfer (SUSE-SU-2020:0555-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description",
    value:
"This update for python-aws-sam-translator, python-boto3,
python-botocore, python-cfn-lint, python-jsonschema, python-nose2,
python-parameterized, python-pathlib2, python-pytest-cov,
python-requests, python-s3transfer, python-jsonpatch,
python-jsonpointer, python-scandir, python-PyYAML fixes the following
issues :

python-cfn-lint was included as a new package in 0.21.4.

python-aws-sam-translator was updated to 1.11.0 :

  - Add ReservedConcurrentExecutions to globals

  - Fix ElasticsearchHttpPostPolicy resource reference

  - Support using AWS::Region in Ref and Sub

  - Documentation and examples updates

  - Add VersionDescription property to Serverless::Function

  - Update ServerlessRepoReadWriteAccessPolicy

  - Add additional template validation

Upgrade to 1.10.0 :

  - Add GSIs to DynamoDBReadPolicy and DynamoDBCrudPolicy

  - Add DynamoDBReconfigurePolicy

  - Add CostExplorerReadOnlyPolicy and
    OrganizationsListAccountsPolicy

  - Add EKSDescribePolicy

  - Add SESBulkTemplatedCrudPolicy

  - Add FilterLogEventsPolicy

  - Add SSMParameterReadPolicy

  - Add SESEmailTemplateCrudPolicy

  - Add s3:PutObjectAcl to S3CrudPolicy

  - Add allow_credentials CORS option

  - Add support for AccessLogSetting and CanarySetting
    Serverless::Api properties

  - Add support for X-Ray in Serverless::Api

  - Add support for MinimumCompressionSize in
    Serverless::Api

  - Add Auth to Serverless::Api globals

  - Remove trailing slashes from APIGW permissions

  - Add SNS FilterPolicy and an example application

  - Add Enabled property to Serverless::Function event
    sources

  - Add support for PermissionsBoundary in
    Serverless::Function

  - Fix boto3 client initialization

  - Add PublicAccessBlockConfiguration property to S3 bucket
    resource

  - Make PAY_PER_REQUEST default mode for
    Serverless::SimpleTable

  - Add limited support for resolving intrinsics in
    Serverless::LayerVersion

  - SAM now uses Flake8

  - Add example application for S3 Events written in Go

  - Updated several example applications

Initial build

  + Version 1.9.0

Add patch to drop compatible releases operator from setup.py, required
for SLES12 as the setuptools version is too old

  + ast_drop-compatible-releases-operator.patch

python-jsonschema was updated to 2.6.0: Improved performance on
CPython by adding caching around ref resolution

Update to version 2.5.0: Improved performance on CPython by adding
caching around ref resolution (#203)

Update to version 2.4.0: Added a CLI (#134)

Added absolute path and absolute schema path to errors (#120)

Added ``relevance``

Meta-schemas are now loaded via ``pkgutil``

Added ``by_relevance`` and ``best_match`` (#91)

Fixed ``format`` to allow adding formats for non-strings (#125)

Fixed the ``uri`` format to reject URI references (#131)

Install /usr/bin/jsonschema with update-alternatives support

python-nose2 was updated to 0.9.1: the prof plugin now uses cProfile
instead of hotshot for profiling

skipped tests now include the user's reason in junit XML's message
field

the prettyassert plugin mishandled multi-line function definitions

Using a plugin's CLI flag when the plugin is already enabled via
config no longer errors

nose2.plugins.prettyassert, enabled with --pretty-assert

Cleanup code for EOLed python versions

Dropped support for distutils.

Result reporter respects failure status set by other plugins

JUnit XML plugin now includes the skip reason in its output

Upgrade to 0.8.0 :

List of changes is too long to show here, see
https://github.com/nose-devs/nose2/blob/master/docs/changelog.rst
changes between 0.6.5 and 0.8.0

Update to 0.7.0: Added parameterized_class feature, for parameterizing
entire test classes (many thanks to @TobyLL for their suggestions and
help testing!)

Fix DeprecationWarning on `inspect.getargs` (thanks @brettdh;
https://github.com/wolever/parameterized/issues/67)

Make sure that `setUp` and `tearDown` methods work correctly (#40)

Raise a ValueError when input is empty (thanks @danielbradburn;
https://github.com/wolever/parameterized/pull/48)

Fix the order when number of cases exceeds 10 (thanks @ntflc;
https://github.com/wolever/parameterized/pull/49)

python-scandir was included in version 2.3.2.

python-requests was updated to version 2.20.1 (bsc#1111622) Fixed bug
with unintended Authorization header stripping for redirects using
default ports (http/80, https/443).

remove restriction for urllib3 

Update to version 2.20.0: Bugfixes

  + Content-Type header parsing is now case-insensitive
    (e.g. charset=utf8 v Charset=utf8).

  + Fixed exception leak where certain redirect urls would
    raise uncaught urllib3 exceptions.

  + Requests removes Authorization header from requests
    redirected from https to http on the same hostname.
    (CVE-2018-18074)

  + should_bypass_proxies now handles URIs without hostnames
    (e.g. files).

Dependencies

  + Requests now supports urllib3 v1.24.

Deprecations

  + Requests has officially stopped support for Python 2.6.

Update to version 2.19.1: Fixed issue where
status_codes.py&Atilde;&cent;&Acirc;&#128;&Acirc;&#153;s init function
failed trying to append to a __doc__ value of None.

Update to version 2.19.0: Improvements

  + Warn about possible slowdown with cryptography version 

Bugfixes

  + Parsing empty Link headers with parse_header_links() no
    longer return one bogus entry.

  + Fixed issue where loading the default certificate bundle
    from a zip archive would raise an IOError.

  + Fixed issue with unexpected ImportError on windows
    system which do not support winreg module.

  + DNS resolution in proxy bypass no longer includes the
    username and password in the request. This also fixes
    the issue of DNS queries failing on macOS.

  + Properly normalize adapter prefixes for url comparison.

  + Passing None as a file pointer to the files param no
    longer raises an exception.

  + Calling copy on a RequestsCookieJar will now preserve
    the cookie policy correctly.

We now support idna v2.7 and urllib3 v1.23.

update to version 2.18.4: Improvements

  + Error messages for invalid headers now include the
    header name for easier debugging

Dependencies

  + We now support idna v2.6.

update to version 2.18.3: Improvements

  + Running $ python -m requests.help now includes the
    installed version of idna.

Bugfixes

  + Fixed issue where Requests would raise ConnectionError
    instead of SSLError when encountering SSL problems when
    using urllib3 v1.22.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1111622"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1122668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/nose-devs/nose2/blob/master/docs/changelog.rst"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/wolever/parameterized/issues/67"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/wolever/parameterized/pull/48"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://github.com/wolever/parameterized/pull/49"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2018-18074/"
  );
  # https://www.suse.com/support/update/announcement/2020/suse-su-20200555-1/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b256b511"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud Crowbar 8:zypper in -t patch
SUSE-OpenStack-Cloud-Crowbar-8-2020-555=1

SUSE OpenStack Cloud 8:zypper in -t patch
SUSE-OpenStack-Cloud-8-2020-555=1

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2020-555=1

SUSE Manager Tools 12:zypper in -t patch
SUSE-SLE-Manager-Tools-12-2020-555=1

SUSE Manager Server 3.2:zypper in -t patch
SUSE-SUSE-Manager-Server-3.2-2020-555=1

SUSE Manager Proxy 3.2:zypper in -t patch
SUSE-SUSE-Manager-Proxy-3.2-2020-555=1

SUSE Linux Enterprise Server for SAP 12-SP3:zypper in -t patch
SUSE-SLE-SAP-12-SP3-2020-555=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2020-555=1

SUSE Linux Enterprise Server for SAP 12-SP1:zypper in -t patch
SUSE-SLE-SAP-12-SP1-2020-555=1

SUSE Linux Enterprise Server 12-SP5:zypper in -t patch
SUSE-SLE-SERVER-12-SP5-2020-555=1

SUSE Linux Enterprise Server 12-SP4:zypper in -t patch
SUSE-SLE-SERVER-12-SP4-2020-555=1

SUSE Linux Enterprise Server 12-SP3-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2020-555=1

SUSE Linux Enterprise Server 12-SP3-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-BCL-2020-555=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2020-555=1

SUSE Linux Enterprise Server 12-SP2-BCL:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-BCL-2020-555=1

SUSE Linux Enterprise Server 12-SP1-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP1-2020-555=1

SUSE Linux Enterprise Point of Sale 12-SP2:zypper in -t patch
SUSE-SLE-POS-12-SP2-2020-555=1

SUSE Linux Enterprise Module for Public Cloud 12:zypper in -t patch
SUSE-SLE-Module-Public-Cloud-12-2020-555=1

SUSE Linux Enterprise Module for Containers 12:zypper in -t patch
SUSE-SLE-Module-Containers-12-2020-555=1

SUSE Linux Enterprise Module for Advanced Systems Management 12:zypper
in -t patch SUSE-SLE-Module-Adv-Systems-Management-12-2020-555=1

SUSE Linux Enterprise High Availability 12-SP5:zypper in -t patch
SUSE-SLE-HA-12-SP5-2020-555=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2020-555=1

SUSE Linux Enterprise High Availability 12-SP1:zypper in -t patch
SUSE-SLE-HA-12-SP1-2020-555=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2020-555=1

SUSE CaaS Platform 3.0 :

To install this update, use the SUSE CaaS Platform Velum dashboard. It
will inform you if it detects new updates and let you then trigger
updating of the complete cluster in a controlled way.

HPE Helion Openstack 8:zypper in -t patch
HPE-Helion-OpenStack-8-2020-555=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18074");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-PyYAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-PyYAML-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-PyYAML-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-PyYAML");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/06");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3|4|5)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3/4/5", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-PyYAML-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-PyYAML-debuginfo-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"4", reference:"python-PyYAML-debugsource-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-PyYAML-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-PyYAML-debuginfo-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-PyYAML-debugsource-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python3-PyYAML-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-PyYAML-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-PyYAML-debuginfo-5.1.2-26.9.4")) flag++;
if (rpm_check(release:"SLES12", sp:"5", reference:"python-PyYAML-debugsource-5.1.2-26.9.4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-aws-sam-translator / python-boto3 / python-botocore / python-cfn-lint / python-jsonschema / python-nose2 / python-parameterized / python-pathlib2 / python-pytest-cov / python-requests / python-s3transfer");
}
