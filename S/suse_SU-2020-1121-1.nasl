#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2020:1121-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(136074);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2022/05/13");

  script_cve_id(
    "CVE-2017-15298",
    "CVE-2018-11233",
    "CVE-2018-11235",
    "CVE-2018-17456",
    "CVE-2019-1348",
    "CVE-2019-1349",
    "CVE-2019-1350",
    "CVE-2019-1351",
    "CVE-2019-1352",
    "CVE-2019-1353",
    "CVE-2019-1354",
    "CVE-2019-1387",
    "CVE-2019-19604",
    "CVE-2020-5260",
    "CVE-2020-11008"
  );

  script_name(english:"SUSE SLED15 / SLES15 Security Update : git (SUSE-SU-2020:1121-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for git fixes the following issues :

Security issues fixed :

CVE-2020-11008: Specially crafted URLs may have tricked the
credentials helper to providing credential information that is not
appropriate for the protocol in use and host being contacted
(bsc#1169936)

git was updated to 2.26.1 (bsc#1169786, jsc#ECO-1628, bsc#1149792)

Fix git-daemon not starting after conversion from sysvinit to systemd
service (bsc#1169605).

CVE-2020-5260: Specially crafted URLs with newline characters could
have been used to make the Git client to send credential information
for a wrong host to the attacker's site bsc#1168930

git 2.26.0 (bsc#1167890, jsc#SLE-11608) :

'git rebase' now uses a different backend that is based on the 'merge'
machinery by default. The 'rebase.backend' configuration variable
reverts to old behaviour when set to 'apply'

Improved handling of sparse checkouts

Improvements to many commands and internal features

git 2.25.2 :

bug fixes to various subcommands in specific operations

git 2.25.1 :

'git commit' now honors advise.statusHints

various updates, bug fixes and documentation updates

git 2.25.0

The branch description ('git branch --edit-description') has been used
to fill the body of the cover letters by the format-patch command;
this has been enhanced so that the subject can also be filled.

A few commands learned to take the pathspec from the standard input or
a named file, instead of taking it as the command line arguments, with
the '--pathspec-from-file' option.

Test updates to prepare for SHA-2 transition continues.

Redo 'git name-rev' to avoid recursive calls.

When all files from some subdirectory were renamed to the root
directory, the directory rename heuristics would fail to detect that
as a rename/merge of the subdirectory to the root directory, which has
been corrected.

HTTP transport had possible allocator/deallocator mismatch, which has
been corrected.

git 2.24.1 :

CVE-2019-1348: The --export-marks option of fast-import is exposed
also via the in-stream command feature export-marks=... and it allows
overwriting arbitrary paths (bsc#1158785)

CVE-2019-1349: on Windows, when submodules are cloned recursively,
under certain circumstances Git could be fooled into using the same
Git directory twice (bsc#1158787)

CVE-2019-1350: Incorrect quoting of command-line arguments allowed
remote code execution during a recursive clone in conjunction with SSH
URLs (bsc#1158788)

CVE-2019-1351: on Windows mistakes drive letters outside of the
US-English alphabet as relative paths (bsc#1158789)

CVE-2019-1352: on Windows was unaware of NTFS Alternate Data Streams
(bsc#1158790)

CVE-2019-1353: when run in the Windows Subsystem for Linux while
accessing a working directory on a regular Windows drive, none of the
NTFS protections were active (bsc#1158791)

CVE-2019-1354: on Windows refuses to write tracked files with
filenames that contain backslashes (bsc#1158792)

CVE-2019-1387: Recursive clones vulnerability that is caused by
too-lax validation of submodule names, allowing very targeted attacks
via remote code execution in recursive clones (bsc#1158793)

CVE-2019-19604: a recursive clone followed by a submodule update could
execute code contained within the repository without the user
explicitly having asked for that (bsc#1158795)

git 2.24.0

The command line parser learned '--end-of-options' notation.

A mechanism to affect the default setting for a (related) group of
configuration variables is introduced.

'git fetch' learned '--set-upstream' option to help those who first
clone from their private fork they intend to push to, add the true
upstream via 'git remote add' and then 'git fetch' from it.

fixes and improvements to UI, workflow and features, bash completion
fixes

git 2.23.0 :

The '--base' option of 'format-patch' computed the patch-ids for
prerequisite patches in an unstable way, which has been updated to
compute in a way that is compatible with 'git patch-id

--stable'.

The 'git log' command by default behaves as if the --mailmap option
was given.

fixes and improvements to UI, workflow and features

git 2.22.1

A relative pathname given to 'git init --template=<path> <repo>' ought
to be relative to the directory 'git init' gets invoked in, but it
instead was made relative to the repository, which has been corrected.
</repo></path>

'git worktree add' used to fail when another worktree connected to the
same repository was corrupt, which has been corrected.

'git am -i --resolved' segfaulted after trying to see a commit as if
it were a tree, which has been corrected.

'git merge --squash' is designed to update the working tree and the
index without creating the commit, and this cannot be countermanded by
adding the '--commit' option; the command now refuses to work when
both options are given.

Update to Unicode 12.1 width table.

'git request-pull' learned to warn when the ref we ask them to pull
from in the local repository and in the published repository are
different.

'git fetch' into a lazy clone forgot to fetch base objects that are
necessary to complete delta in a thin packfile, which has been
corrected.

The URL decoding code has been updated to avoid going past the end of
the string while parsing %-<hex>-<hex> sequence. </hex></hex>

'git clean' silently skipped a path when it cannot lstat() it; now it
gives a warning.

'git rm' to resolve a conflicted path leaked an internal message
'needs merge' before actually removing the path, which was confusing.
This has been corrected.

Many more bugfixes and code cleanups.

removal of SuSEfirewall2 service, since SuSEfirewall2 has been
replaced by firewalld.

partial fix for git instaweb giving 500 error (bsc#1112230)

git 2.22.0

The filter specification '--filter=sparse:path=<path>' used to create
a lazy/partial clone has been removed. Using a blob that is part of
the project as sparse specification is still supported with the
'--filter=sparse:oid=<blob>' option </blob></path>

'git checkout --no-overlay' can be used to trigger a new mode of
checking out paths out of the tree-ish, that allows paths that match
the pathspec that are in the current index and working tree and are
not in the tree-ish.

Four new configuration variables {author,committer}.{name,email} have
been introduced to override user.{name,email} in more specific cases.

'git branch' learned a new subcommand '--show-current'.

The command line completion (in contrib/) has been taught to complete
more subcommand parameters.

The completion helper code now pays attention to repository-local
configuration (when available), which allows --list-cmds to honour a
repository specific setting of completion.commands, for example.

The list of conflicted paths shown in the editor while concluding a
conflicted merge was shown above the scissors line when the clean-up
mode is set to 'scissors', even though it was commented out just like
the list of updated paths and other information to help the user
explain the merge better.

'git rebase' that was reimplemented in C did not set ORIG_HEAD
correctly, which has been corrected.

'git worktree add' used to do a 'find an available name with stat and
then mkdir', which is race-prone. This has been fixed by using mkdir
and reacting to EEXIST in a loop.

Move to DocBook 5.x. Asciidoctor 2.x no longer supports the legacy
DocBook 4.5 format.

update git-web AppArmor profile for bash and tar usrMerge
(bsc#1132350)

git 2.21.0

Historically, the '-m' (mainline) option can only be used for 'git
cherry-pick' and 'git revert' when working with a merge commit. This
version of Git no longer warns or errors out when working with a
single-parent commit, as long as the argument to the '-m' option is 1
(i.e. it has only one parent, and the request is to pick or revert
relative to that first parent). Scripts that relied on the behaviour
may get broken with this change.

Small fixes and features for fast-export and fast-import.

The 'http.version' configuration variable can be used with recent
enough versions of cURL library to force the version of HTTP used to
talk when fetching and pushing.

'git push $there $src:$dst' rejects when $dst is not a fully qualified
refname and it is not clear what the end user meant.

Update 'git multimail' from the upstream.

A new date format '--date=human' that morphs its output depending on
how far the time is from the current time has been introduced.
'--date=auto:human' can be used to use this new format (or any
existing format) when the output is going to the pager or to the
terminal, and otherwise the default format.

Fix worktree creation race (bsc#1114225).

add shadow build dependency to the -daemon subpackage.

git 2.20.1 :

portability fixes

'git help -a' did not work well when an overly long alias was defined

no longer squelched an error message when the run_command API failed
to run a missing command

git 2.20.0

'git help -a' now gives verbose output (same as 'git help -av'). Those
who want the old output may say 'git help --no-verbose -a'..

'git send-email' learned to grab address-looking string on any trailer
whose name ends with '-by'.

'git format-patch' learned new '--interdiff' and '--range-diff'
options to explain the difference between this version and the
previous attempt in the cover letter (or after the three-dashes as a
comment).

Developer builds now use -Wunused-function compilation option.

Fix a bug in which the same path could be registered under multiple
worktree entries if the path was missing (for instance, was removed
manually). Also, as a convenience, expand the number of cases in which

--force is applicable.

The overly large Documentation/config.txt file have been split into
million little pieces. This potentially allows each individual piece
to be included into the manual page of the command it affects more
easily.

Malformed or crafted data in packstream can make our code attempt to
read or write past the allocated buffer and abort, instead of
reporting an error, which has been fixed.

Fix for a long-standing bug that leaves the index file corrupt when it
shrinks during a partial commit.

'git merge' and 'git pull' that merges into an unborn branch used to
completely ignore '--verify-signatures', which has been corrected.

...and much more features and fixes

git 2.19.2 :

various bug fixes for multiple subcommands and operations

git 2.19.1 :

CVE-2018-17456: Specially crafted .gitmodules files may have allowed
arbitrary code execution when the repository is cloned with

--recurse-submodules (bsc#1110949)

git 2.19.0 :

'git diff' compares the index and the working tree. For paths added
with intent-to-add bit, the command shows the full contents of them as
added, but the paths themselves were not marked as new files. They are
now shown as new by default.

'git apply' learned the '--intent-to-add' option so that an otherwise
working-tree-only application of a patch will add new paths to the
index marked with the 'intent-to-add' bit.

'git grep' learned the '--column' option that gives not just the line
number but the column number of the hit.

The '-l' option in 'git branch -l' is an unfortunate short-hand for
'--create-reflog', but many users, both old and new, somehow expect it
to be something else, perhaps '--list'. This step warns when '-l' is
used as a short-hand for '--create-reflog' and warns about the future
repurposing of the it when it is used.

The userdiff pattern for .php has been updated.

The content-transfer-encoding of the message 'git send-email' sends
out by default was 8bit, which can cause trouble when there is an
overlong line to bust RFC 5322/2822 limit. A new option 'auto' to
automatically switch to quoted-printable when there is such a line in
the payload has been introduced and is made the default.

'git checkout' and 'git worktree add' learned to honor
checkout.defaultRemote when auto-vivifying a local branch out of a
remote tracking branch in a repository with multiple remotes that have
tracking branches that share the same names. (merge 8d7b558bae
ab/checkout-default-remote later to maint).

'git grep' learned the '--only-matching' option.

'git rebase --rebase-merges' mode now handles octopus merges as well.

Add a server-side knob to skip commits in exponential/fibbonacci
stride in an attempt to cover wider swath of history with a smaller
number of iterations, potentially accepting a larger packfile
transfer, instead of going back one commit a time during common
ancestor discovery during the 'git fetch' transaction. (merge
42cc7485a2 jt/fetch-negotiator-skipping later to maint).

A new configuration variable core.usereplacerefs has been added,
primarily to help server installations that want to ignore the replace
mechanism altogether.

Teach 'git tag -s' etc. a few configuration variables (gpg.format that
can be set to 'openpgp' or 'x509', and gpg.<format>.program that is
used to specify what program to use to deal with the format) to allow
x.509 certs with CMS via 'gpgsm' to be used instead of openpgp via
'gnupg'. </format>

Many more strings are prepared for l10n.

'git p4 submit' learns to ask its own pre-submit hook if it should
continue with submitting.

The test performed at the receiving end of 'git push' to prevent bad
objects from entering repository can be customized via receive.fsck.*
configuration variables; we now have gained a counterpart to do the
same on the 'git fetch' side, with fetch.fsck.* configuration
variables.

'git pull --rebase=interactive' learned 'i' as a short-hand for
'interactive'.

'git instaweb' has been adjusted to run better with newer Apache on
RedHat based distros.

'git range-diff' is a reimplementation of 'git tbdiff' that lets us
compare individual patches in two iterations of a topic.

The sideband code learned to optionally paint selected keywords at the
beginning of incoming lines on the receiving end.

'git branch --list' learned to take the default sort order from the
'branch.sort' configuration variable, just like 'git tag --list' pays
attention to 'tag.sort'.

'git worktree' command learned '--quiet' option to make it less
verbose.

git 2.18.0 :

improvements to rename detection logic

When built with more recent cURL, GIT_SSL_VERSION can now specify
'tlsv1.3' as its value.

'git mergetools' learned talking to guiffy.

various other workflow improvements and fixes

performance improvements and other developer visible fixes

git 2.17.1

Submodule 'names' come from the untrusted .gitmodules file, but we
blindly append them to $GIT_DIR/modules to create our on-disk repo
paths. This means you can do bad things by putting '../' into the
name. We now enforce some rules for submodule names which will cause
Git to ignore these malicious names (CVE-2018-11235, bsc#1095219)

It was possible to trick the code that sanity-checks paths on NTFS
into reading random piece of memory (CVE-2018-11233, bsc#1095218)

Support on the server side to reject pushes to repositories that
attempt to create such problematic .gitmodules file etc. as tracked
contents, to help hosting sites protect their customers by preventing
malicious contents from spreading.

git 2.17.0 :

'diff' family of commands learned '--find-object=<object-id>' option
to limit the findings to changes that involve the named object.
</object-id>

'git format-patch' learned to give 72-cols to diffstat, which is
consistent with other line length limits the subcommand uses for its
output meant for e-mails.

The log from 'git daemon' can be redirected with a new option; one
relevant use case is to send the log to standard error (instead of
syslog) when running it from inetd.

'git rebase' learned to take '--allow-empty-message' option.

'git am' has learned the '--quit' option, in addition to the existing
'--abort' option; having the pair mirrors a few other commands like
'rebase' and 'cherry-pick'.

'git worktree add' learned to run the post-checkout hook, just like
'git clone' runs it upon the initial checkout.

'git tag' learned an explicit '--edit' option that allows the message
given via '-m' and '-F' to be further edited.

'git fetch --prune-tags' may be used as a handy short-hand for getting
rid of stale tags that are locally held.

The new '--show-current-patch' option gives an end-user facing way to
get the diff being applied when 'git rebase' (and 'git am') stops with
a conflict.

'git add -p' used to offer '/' (look for a matching hunk) as a choice,
even there was only one hunk, which has been corrected. Also the
single-key help is now given only for keys that are enabled (e.g. help
for '/' won't be shown when there is only one hunk).

Since Git 1.7.9, 'git merge' defaulted to --no-ff (i.e. even when the
side branch being merged is a descendant of the current commit, create
a merge commit instead of fast-forwarding) when merging a tag object.
This was appropriate default for integrators who pull signed tags from
their downstream contributors, but caused an unnecessary merges when
used by downstream contributors who habitually 'catch up' their topic
branches with tagged releases from the upstream. Update 'git merge' to
default to --no-ff only when merging a tag object that does *not* sit
at its usual place in refs/tags/ hierarchy, and allow fast-forwarding
otherwise, to mitigate the problem.

'git status' can spend a lot of cycles to compute the relation between
the current branch and its upstream, which can now be disabled with
'--no-ahead-behind' option.

'git diff' and friends learned funcname patterns for Go language
source files.

'git send-email' learned '--reply-to=<address>' option. </address>

Funcname pattern used for C# now recognizes 'async' keyword.

In a way similar to how 'git tag' learned to honor the pager setting
only in the list mode, 'git config' learned to ignore the pager
setting when it is used for setting values (i.e. when the purpose of
the operation is not to 'show').

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1063412");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1095218");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1095219");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1110949");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1112230");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1114225");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1132350");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1149792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1156651");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158787");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158789");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158790");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158791");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158793");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1158795");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1167890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1168930");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169605");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169786");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1169936");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2017-15298/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11233/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-11235/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17456/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1348/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1349/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1350/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1351/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1352/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1353/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1354/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-1387/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2019-19604/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-11008/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-5260/");
  # https://www.suse.com/support/update/announcement/2020/suse-su-20201121-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47879213");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-SP1-2020-1121=1

SUSE Linux Enterprise Module for Development Tools 15-SP1 :

zypper in -t patch
SUSE-SLE-Module-Development-Tools-15-SP1-2020-1121=1

SUSE Linux Enterprise Module for Basesystem 15-SP1 :

zypper in -t patch SUSE-SLE-Module-Basesystem-15-SP1-2020-1121=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-19604");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-1353");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Malicious Git HTTP Server For CVE-2018-17456');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-arch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-gnome-keyring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-gnome-keyring-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-libsecret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-credential-libsecret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-cvs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-email");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-p4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-svn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-svn-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:git-web");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gitk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2022 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP1", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(1)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP1", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-arch-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-core-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-core-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-gnome-keyring-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-gnome-keyring-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-libsecret-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-credential-libsecret-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-cvs-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-daemon-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-daemon-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-debugsource-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-email-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-gui-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-p4-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-svn-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-svn-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"git-web-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLES15", sp:"1", reference:"gitk-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-arch-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-core-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-core-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-gnome-keyring-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-gnome-keyring-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-libsecret-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-credential-libsecret-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-cvs-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-daemon-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-daemon-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-debugsource-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-email-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-gui-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-p4-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-svn-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-svn-debuginfo-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"git-web-2.26.1-3.25.2")) flag++;
if (rpm_check(release:"SLED15", sp:"1", reference:"gitk-2.26.1-3.25.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "git");
}
