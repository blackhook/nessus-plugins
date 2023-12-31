#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The text description of this plugin is (C) Novell, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58891);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/05");

  script_cve_id("CVE-2011-1015", "CVE-2011-3389", "CVE-2012-1150");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"SuSE 10 Security Update : Python (ZYPP Patch Number 8080) (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SuSE 10 host is missing a security-related patch.");
  script_set_attribute(attribute:"description", value:
"The following issues have been fixed in this update :

  - hash randomization issues (CVE-2012-115) (see below)

  - SimpleHTTPServer XSS. (CVE-2011-1015)

  - SSL BEAST vulnerability (CVE-2011-3389) The hash
    randomization fix is by default disabled to keep
    compatibility with existing python code when it extracts
    hashes.

To enable the hash seed randomization you can either use :

  - pass -R to the python interpreter commandline.

  - set the environment variable PYTHONHASHSEED=random to
    enable it for programs. You can also set this
    environment variable to a fixed hash seed by specifying
    a integer value between 0 and MAX_UINT.

In generally enabling this is only needed when malicious third parties
can inject values into your hash tables.");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-1015.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2011-3389.html");
  script_set_attribute(attribute:"see_also", value:"http://support.novell.com/security/cve/CVE-2012-1150.html");
  script_set_attribute(attribute:"solution", value:
"Apply ZYPP patch number 8080.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");
if (!get_kb_item("Host/SuSE/release")) exit(0, "The host is not running SuSE.");
if (!get_kb_item("Host/SuSE/rpm-list")) exit(1, "Could not obtain the list of installed packages.");

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) exit(1, "Failed to determine the architecture type.");
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") exit(1, "Local checks for SuSE 10 on the '"+cpu+"' architecture have not been implemented.");


flag = 0;
if (rpm_check(release:"SLED10", sp:4, reference:"python-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"python-curses-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"python-devel-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"python-gdbm-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"python-tk-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, reference:"python-xml-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLED10", sp:4, cpu:"x86_64", reference:"python-32bit-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-curses-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-demo-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-devel-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-doc-2.4.2-18.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-doc-pdf-2.4.2-18.41.3")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-gdbm-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-idle-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-tk-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, reference:"python-xml-2.4.2-18.41.2")) flag++;
if (rpm_check(release:"SLES10", sp:4, cpu:"x86_64", reference:"python-32bit-2.4.2-18.41.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else exit(0, "The host is not affected.");
