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
  script_id(49826);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_cve_id("CVE-2009-1195", "CVE-2009-1890", "CVE-2009-1891", "CVE-2009-3094", "CVE-2009-3095");

  script_name(english:"SuSE 10 Security Update : Apache 2 (ZYPP Patch Number 6572)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SuSE 10 host is missing a security-related patch."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update of the Apache webserver fixes various security issues :

  - the option IncludesNOEXEC could be bypassed via
    .htaccess. (CVE-2009-1195)

  - mod_proxy could run into an infinite loop when used as
    reverse proxy. (CVE-2009-1890)

  - mod_deflate continued to compress large files even after
    a network connection was closed, causing mod_deflate to
    consume large amounts of CPU. (CVE-2009-1891)

  - The ap_proxy_ftp_handler function in
    modules/proxy/proxy_ftp.c in the mod_proxy_ftp module
    allows remote FTP servers to cause a denial of service
    (NULL pointer dereference and child process crash) via a
    malformed reply to an EPSV command. (CVE-2009-3094)

  - access restriction bypass in mod_proxy_ftp module.
    (CVE-2009-3095)

Also a incompatibility between mod_cache and mod_rewrite was fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1195.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1890.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-1891.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3094.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.novell.com/security/cve/CVE-2009-3095.html"
  );
  script_set_attribute(attribute:"solution", value:"Apply ZYPP patch number 6572.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(16, 119, 189, 264, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:suse:suse_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

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
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-2.2.3-16.28.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-devel-2.2.3-16.28.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-doc-2.2.3-16.28.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-example-pages-2.2.3-16.28.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-prefork-2.2.3-16.28.1")) flag++;
if (rpm_check(release:"SLES10", sp:3, reference:"apache2-worker-2.2.3-16.28.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else exit(0, "The host is not affected.");
