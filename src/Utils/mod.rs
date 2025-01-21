use std::{
	fs,
	path,
	process,
	fmt::{self, Display, Formatter}, 
	error::Error, 
	io, 
	sync::Arc
};

pub mod archive;

pub mod zip_manager;

enum TargetType {
	Dir,
	File,
	Symlink,
}

impl TargetType {
	pub fn dir() -> Self {
		Self::Dir
	}
	pub fn file() -> Self {
		Self::File
	}
	pub fn symlink() -> Self {
		Self::Symlink
	}
}

struct Utils;
