#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Slackware Security Advisory 2009-209-01. The text 
# itself is copyright (C) Slackware Linux, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(40408);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/14");

  script_bugtraq_id(35765, 35766, 35767, 35769, 35770, 35772, 35773, 35775);
  script_xref(name:"SSA", value:"2009-209-01");

  script_name(english:"Slackware 12.2 : mozilla-firefox (SSA:2009-209-01)");
  script_summary(english:"Checks for updated package in /var/log/packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Slackware host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A new mozilla-firefox package is available for Slackware 12.2 to fix
security issues. The updated packages may also be used with Slackware
11.0 or newer."
  );
  # http://www.mozilla.org/security/known-vulnerabilities/firefox30.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d7d74da4"
  );
  # http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.328828
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f5e60abd"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected mozilla-firefox package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:slackware:slackware_linux:mozilla-firefox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:slackware:slackware_linux:12.2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/29");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Slackware Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("slackware.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Slackware/release")) audit(AUDIT_OS_NOT, "Slackware");
if (!get_kb_item("Host/Slackware/packages")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Slackware", cpu);


flag = 0;
if (slackware_check(osver:"12.2", pkgname:"mozilla-firefox", pkgver:"3.0.12", pkgarch:"i686", pkgnum:"1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:slackware_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
