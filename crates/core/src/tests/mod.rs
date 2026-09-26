#![allow(non_snake_case)]

#[cfg(all(test, feature = "archive"))]
mod ArchiveTests;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod KyberKeyTests;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod KyberTests;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod SignatureTests;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod MacroTests;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod LegacyCleanupTests;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod BuilderPatternTests;

#[cfg(test)]
mod Phase3Tests;

// `activate_log`/`log_activity!`/`write_log!`/`LOGGER` are unconditional
// (re-exported from `crypt_guard_proc`), so this module needs no
// `legacy-pqclean` gate — only the whole tree's `cgv2-compat` test gate.
#[cfg(test)]
mod LoggingTests;
