#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-d58eb75449.
#

include("compat.inc");

if (description)
{
  script_id(128653);
  script_version("1.4");
  script_cvs_date("Date: 2019/12/27");

  script_cve_id("CVE-2019-16056");
  script_xref(name:"FEDORA", value:"2019-d58eb75449");

  script_name(english:"Fedora 29 : python38 (2019-d58eb75449)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"# This is a beta preview of Python 3.8

Python 3.8 is still in development. This release, 3.8.0b4 is the last
of four planned beta release previews. Beta release previews are
intended to give the wider community the opportunity to test new
features and bug fixes and to prepare their projects to support the
new feature release.

# Call to action

We **strongly encourage** maintainers of third-party Python projects
to **test with 3.8** during the beta phase and report issues found to
[the Python bug tracker](https://bugs.python.org) as soon as possible.
While the release is planned to be feature complete entering the beta
phase, it is possible that features may be modified or, in rare cases,
deleted up until the start of the release candidate phase
(2019-09-30). Our goal is have no ABI changes after beta 3 and no code
changes after 3.8.0rc1, the release candidate. To achieve that, it
will be extremely important to get as much exposure for 3.8 as
possible during the beta phase.

Please keep in mind that this is a preview release and its use is
**not** recommended for production environments.

# Major new features of the 3.8 series, compared to 3.7

Some of the new major new features and changes in Python 3.8 are :

  - [PEP 572](https://www.python.org/dev/peps/pep-0572/),
    Assignment expressions

  - [PEP 570](https://www.python.org/dev/peps/pep-0570/),
    Positional-only arguments

  - [PEP 587](https://www.python.org/dev/peps/pep-0587/),
    Python Initialization Configuration (improved embedding)

  - [PEP 590](https://www.python.org/dev/peps/pep-0590/),
    Vectorcall: a fast calling protocol for CPython

  - [PEP 578](https://www.python.org/dev/peps/pep-0578),
    Runtime audit hooks

  - [PEP 574](https://www.python.org/dev/peps/pep-0574),
    Pickle protocol 5 with out-of-band data

  - Typing-related: [PEP
    591](https://www.python.org/dev/peps/pep-0591) (Final
    qualifier), [PEP
    586](https://www.python.org/dev/peps/pep-0586) (Literal
    types), and [PEP
    589](https://www.python.org/dev/peps/pep-0589)
    (TypedDict)

  - Parallel filesystem cache for compiled bytecode

  - Debug builds share ABI as release builds

  - f-strings support a handy `=` specifier for debugging

  - `continue` is now legal in `finally:` blocks

  - on Windows, the default `asyncio` event loop is now
    `ProactorEventLoop`

  - on macOS, the _spawn_ start method is now used by
    default in `multiprocessing`

  - `multiprocessing` can now use shared memory segments to
    avoid pickling costs between processes

  - `typed_ast` is merged back to CPython

  - `LOAD_GLOBAL` is now 40% faster

  - `pickle` now uses Protocol 4 by default, improving
    performance

There are many other interesting changes, please consult the 'What's
New' page in the documentation for a full list.

The next pre-release of Python 3.8 and the first release candidate
will be 3.8.0rc1, currently scheduled for 2019-09-30.

# More resources

  - [Online Documentation](https://docs.python.org/3.8/)

  - [PEP 569](https://www.python.org/dev/peps/pep-0569/),
    3.8 Release Schedule

  - Report bugs at
    [bugs.python.org](https://bugs.python.org) or via
    [Fedora
    Bugzilla](https://bugz.fedoraproject.org/python38)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-d58eb75449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.python.org"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0569/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0570/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0572/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0574"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0578"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0587/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0590/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.python.org/dev/peps/pep-0591"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected python38 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:python38");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/11");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"python38-3.8.0~b4-1.fc29")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python38");
}
