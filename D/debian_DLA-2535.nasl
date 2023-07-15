#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2535-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(145531);

  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/02/03");

  script_cve_id("CVE-2017-7481", "CVE-2019-10156", "CVE-2019-14846", "CVE-2019-14904");
  script_name(english:"Debian DLA-2535-1 : ansible security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"CVE-2017-7481

Ansible fails to properly mark lookup-plugin results as unsafe. If an
attacker could control the results of lookup() calls, they could
inject Unicode strings to be parsed by the jinja2 templating system,
resulting in code execution. By default, the jinja2 templating
language is now marked as 'unsafe' and is not evaluated.

CVE-2019-10156

A flaw was discovered in the way Ansible templating was implemented,
causing the possibility of information disclosure through unexpected
variable substitution. By taking advantage of unintended variable
substitution the content of any variable may be disclosed.

CVE-2019-14846

Ansible was logging at the DEBUG level which lead to a disclosure of
credentials if a plugin used a library that logged credentials at the
DEBUG level. This flaw does not affect Ansible modules, as those are
executed in a separate process.

CVE-2019-14904

A flaw was found in the solaris_zone module from the Ansible Community
modules. When setting the name for the zone on the Solaris host, the
zone name is checked by listing the process with the 'ps' bare command
on the remote machine. An attacker could take advantage of this flaw
by crafting the name of the zone and executing arbitrary commands in
the remote host.

For Debian 9 stretch, these problems have been fixed in version
2.2.1.0-2+deb9u2.

We recommend that you upgrade your ansible packages.

For the detailed security status of ansible please refer to its
security tracker page at:
https://security-tracker.debian.org/tracker/ansible

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2021/01/msg00023.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/ansible"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/ansible"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade the affected ansible package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7481");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"9.0", prefix:"ansible", reference:"2.2.1.0-2+deb9u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
