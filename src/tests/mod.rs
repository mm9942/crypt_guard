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

#[cfg(test)]
mod ze_end;

#[cfg(all(test, feature = "legacy-pqclean"))]
mod BuilderPatternTests;

#[cfg(test)]
mod Phase3Tests;
