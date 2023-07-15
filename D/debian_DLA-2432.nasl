#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2432-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143107);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/11/25");

  script_cve_id("CVE-2018-19351", "CVE-2018-21030", "CVE-2018-8768");

  script_name(english:"Debian DLA-2432-1 : jupyter-notebook security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Several vulnerabilities have been discovered in jupyter-notebook.

CVE-2018-8768

A maliciously forged notebook file can bypass sanitization to execute
JavaScript in the notebook context. Specifically, invalid HTML is
'fixed' by jQuery after sanitization, making it dangerous.

CVE-2018-19351

allows XSS via an untrusted notebook because nbconvert responses are
considered to have the same origin as the notebook server.

CVE-2018-21030

jupyter-notebook does not use a CSP header to treat served files as
belonging to a separate origin. Thus, for example, an XSS payload can
be placed in an SVG document.

For Debian 9 stretch, these problems have been fixed in version
4.2.3-4+deb9u1.

We recommend that you upgrade your jupyter-notebook packages.

For the detailed security status of jupyter-notebook please refer to
its security tracker page at:
https://security-tracker.debian.org/tracker/jupyter-notebook

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2020/11/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/jupyter-notebook"
  );
  # https://security-tracker.debian.org/tracker/source-package/jupyter-notebook
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e187e811"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8768");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jupyter-notebook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-notebook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-notebook-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-notebook");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"jupyter-notebook", reference:"4.2.3-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-notebook", reference:"4.2.3-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python-notebook-doc", reference:"4.2.3-4+deb9u1")) flag++;
if (deb_check(release:"9.0", prefix:"python3-notebook", reference:"4.2.3-4+deb9u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
