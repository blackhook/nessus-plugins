#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-2480-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(143512);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/12/06");

  script_cve_id("CVE-2020-16846", "CVE-2020-28243", "CVE-2021-25282", "CVE-2021-25284", "CVE-2021-3197");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/05/03");
  script_xref(name:"CEA-ID", value:"CEA-2020-0134");

  script_name(english:"Debian DLA-2480-2 : salt regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description",
    value:
"Past security updates of Salt, a remote execution manager, introduced
regressions for which follow-up fixes were published :

CVE 2020-16846 regression

'salt-ssh' master key initialization fails

CVE 2021-3197 regression

Valid parameters are discarded for the SSHClient

CVE 2020-28243 follow-up

Prevent argument injection in restartcheck

CVE 2021-25282 regression

pillar_roots.write cannot write to subdirs

CVE 2021-25284 regression

The 'cmd.run' function crashes if passing tuple arg

For Debian 9 stretch, this problem has been fixed in version
2016.11.2+ds-1+deb9u10.

We recommend that you upgrade your salt packages.

For the detailed security status of salt please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/salt

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2022/01/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/salt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/salt"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3197");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SaltStack Salt REST API Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-minion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:salt-syndic");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/07");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");
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
if (deb_check(release:"9.0", prefix:"salt-api", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-cloud", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-common", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-doc", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-master", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-minion", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-proxy", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-ssh", reference:"2016.11.2+ds-1+deb9u10")) flag++;
if (deb_check(release:"9.0", prefix:"salt-syndic", reference:"2016.11.2+ds-1+deb9u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
