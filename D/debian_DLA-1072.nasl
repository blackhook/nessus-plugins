#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1072-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(102886);
  script_version("3.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/01/11");

  script_cve_id("CVE-2017-1000115", "CVE-2017-1000116");

  script_name(english:"Debian DLA-1072-1 : mercurial security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two significant vulnerabilities were found in the Mercurial version
control system which could lead to shell injection attacks and
out-of-tree file overwrite.

CVE-2017-1000115

Mercurial's symlink auditing was incomplete prior to 4.3, and could be
abused to write to files outside the repository.

CVE-2017-1000116

Mercurial was not sanitizing hostnames passed to ssh, allowing shell
injection attacks on clients by specifying a hostname starting with
-oProxyCommand. This vulnerability is similar to those in Git
(CVE-2017-1000117) and Subversion (CVE-2017-9800).

For Debian 7 'Wheezy', these problems have been fixed in version
2.2.2-4+deb7u5.

We recommend that you upgrade your mercurial packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/08/msg00032.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/mercurial"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected mercurial, and mercurial-common packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mercurial");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mercurial-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/09/01");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"7.0", prefix:"mercurial", reference:"2.2.2-4+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"mercurial-common", reference:"2.2.2-4+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
