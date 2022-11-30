#![warn(clippy::pedantic)]
#![warn(clippy::nursery)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_precision_loss)]
#![allow(clippy::cast_possible_truncation)]
#![warn(future_incompatible)]
#![warn(nonstandard_style)]
#![warn(rust_2018_idioms)]

use anyhow::Result;
use chrono::{DateTime, Local};
use clap::{Parser, ValueEnum};
use libc::{
    ioctl, mode_t, winsize, STDOUT_FILENO, S_IRGRP, S_IROTH, S_IRUSR, S_ISGID, S_ISUID, S_ISVTX,
    S_IWGRP, S_IWOTH, S_IWUSR, S_IXGRP, S_IXOTH, S_IXUSR, TIOCGWINSZ,
};
use lscolors::LsColors;
use number_prefix::NumberPrefix;
use once_cell::sync::Lazy;
use regex::Regex;
use std::{
    fs::{read_link, Metadata},
    io::{self, stdout, BufWriter, Write},
    mem::zeroed,
    os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    ptr::addr_of_mut,
    time::{Duration, UNIX_EPOCH},
};
use term_grid::{Cell, Direction, Filling, Grid, GridOptions};
use users::{get_group_by_gid, get_user_by_uid};
use walkdir::{DirEntry, WalkDir};

static DISPLAY_WIDTH: Lazy<usize> = Lazy::new(|| term_width().unwrap_or(80) as usize);
static CURRENT_YEAR: Lazy<String> = Lazy::new(|| {
    let date = chrono::offset::Local::now();
    date.format("%Y").to_string()
});

fn term_width() -> io::Result<u16> {
    unsafe {
        let mut size: winsize = zeroed();
        cvt(ioctl(STDOUT_FILENO, TIOCGWINSZ, addr_of_mut!(size)))?;
        Ok(size.ws_xpixel)
    }
}

/// Convert an error code into an actual error.
fn cvt(t: i32) -> io::Result<i32> {
    if t == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(t)
    }
}

macro_rules! has {
    ($mode:expr, $perm:expr) => {
        $mode & $perm != 0
    };
}

#[allow(clippy::struct_excessive_bools)]
#[derive(Parser, Debug)]
#[command(version, max_term_width = *DISPLAY_WIDTH)]
struct Args {
    /// Specify the type of the items. Can be specified multiple times.
    #[arg(long = "type", value_enum)]
    types: Option<Vec<Type>>,

    /// Recurse into directories.
    #[arg(short = 'R', long = "recurse")]
    recursive: bool,

    /// Show hidden and 'dot' files.
    #[arg(short = 'a', long = "all")]
    all: bool,

    /// Display extended details and attributes.
    #[arg(short = 'l', long = "long")]
    long: bool,

    /// Returns the results that doesn't match instead of the results that does.
    #[arg(long = "invert")]
    invert: bool,

    /// List files size using only bytes, without any prefixes.
    #[arg(short = 'B', long = "bytes")]
    bytes: bool,

    /// Displays files inode number
    #[arg(short = 'i', long = "inode")]
    inode: bool,

    /// Ignore files matching the specified pattern.
    #[arg(short = 'I', long = "ignore")]
    ignore: Option<Regex>,

    /// Whether or not rpsc should use colored output.
    #[arg(long = "color", default_value = "auto", value_enum)]
    color: Color,

    /// Lists file whose permissions string matches the given regex.
    #[arg(short = 'p')]
    permission_string: Option<Regex>,

    /// List files whose octal permissions matches the given regex.
    #[arg(short = 'o')]
    permission_number: Option<Regex>,

    /// Lists each files permissions in an octal format.
    #[arg(long = "octal-permissions")]
    octal_permissions: bool,

    /// Specify the user that must own the files.
    #[arg(long = "owner")]
    owner: Option<String>,

    /// Specify the group that must own the files.
    #[arg(long = "group")]
    group: Option<String>,

    /// Specify that the files must have extended attributes. [Conflicts with --no-xattr]
    #[arg(long = "xattr", conflicts_with = "no_xattr")]
    xattr: bool,

    /// Specify that the files must not have extended attributes. [Conflicts with --xattr]
    #[arg(long = "no-xattr", conflicts_with = "xattr")]
    no_xattr: bool,

    /// Specify the number of hardlinks the files must have.
    #[arg(long = "hardlinks")]
    hardlinks: Option<u64>,

    /// Specify which timestamp field to list
    #[arg(long = "time", value_enum, default_value = "modified")]
    time: Time,

    /// Specify the style used to display time (e.g. %H-%M)
    #[arg(long = "time-style")]
    time_style: Option<String>,

    /// Displays files whose inode number matches the given regex.
    #[arg(long = "match-inode")]
    match_inode: Option<Regex>,

    /// Displays files whose time matches the given regex.
    #[arg(long = "match-time")]
    match_time: Option<Regex>,

    /// Displays file whose size matches the given regex.
    #[arg(long = "match-size")]
    match_size: Option<Regex>,

    /// Set max recursion depth.
    #[arg(short = 'L', long = "max-depth")]
    max_depth: Option<usize>,

    /// The path of the directory that rpsc should search into.
    #[arg(default_value = ".", value_parser = |path: &str| {
        match PathBuf::from(path).exists() {
            true => Ok(path.to_string()),
            false => Err("path does not exists")
        }})]
    path: String,

    //
    // The following fields are not command line arguments but are evaluated based on the passed
    // command line arguments. They are set at the beginning of the program, after parsing command
    // line arguments.
    //
    // Whether or not the program should use colors (in case auto is set, we use colors if stdout
    // is a tty).
    #[arg(skip)]
    should_use_colors: bool,
    // Whether or not --xattr or --no-xattr was passed, and which one was passed. We regroup both
    // argument as one and the same.
    #[arg(skip)]
    attributes: Option<bool>,
}

impl Args {
    /// Sets the `should_use_colors` and `attributes` fields of self based on command line
    /// arguments.
    fn evaluate(mut self) -> Self {
        self.should_use_colors = match self.color {
            Color::Always => true,
            Color::Never => false,
            Color::Auto => {
                unsafe {
                    libc::isatty(libc::STDOUT_FILENO) != 0 // Colors only if stdout is a tty.
                }
            }
        };
        self.attributes = if self.xattr {
            Some(true)
        } else if self.no_xattr {
            Some(false)
        } else {
            None
        };
        self
    }
}

/// All possible values for the --color argument.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Color {
    Always,
    Auto,
    Never,
}

/// All possible file types.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Type {
    File,
    Directory,
    Symlink,
    Fifo,
    Socket,
    Character,
    Block,
}

/// All displayable dates for files.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum Time {
    Modified,
    Created,
    Accessed,
    Changed,
}

/// Represents a file system item.
struct Item<'a> {
    entry: DirEntry,
    metadata: Metadata,
    bytes_only: bool,
    time: Time,
    time_style: &'a Option<String>,
}

impl<'a> Item<'a> {
    const fn new(entry: DirEntry, metadata: Metadata, args: &'a Args) -> Self {
        Self {
            entry,
            metadata,
            bytes_only: args.bytes,
            time: args.time,
            time_style: &args.time_style,
        }
    }

    /// Returns the character associated with the type of the file.
    fn type_char(&self) -> char {
        if self.entry.file_type().is_file() {
            '-'
        } else if self.entry.file_type().is_dir() {
            'd'
        } else if self.entry.file_type().is_symlink() {
            'l'
        } else if self.entry.file_type().is_fifo() {
            'p'
        } else if self.entry.file_type().is_char_device() {
            'c'
        } else if self.entry.file_type().is_block_device() {
            'b'
        } else {
            's'
        }
    }

    /// Gets the permissions of the file displayed as a string of 9 characters.
    #[allow(clippy::if_not_else)]
    fn permission_string(&self) -> String {
        let mut result = String::with_capacity(9);
        let mode = self.metadata.permissions().mode() as mode_t;

        result.push(if has!(mode, S_IRUSR) { 'r' } else { '-' });
        result.push(if has!(mode, S_IWUSR) { 'w' } else { '-' });
        result.push(if has!(mode, S_ISUID as mode_t) {
            if has!(mode, S_IXUSR) {
                's'
            } else {
                'S'
            }
        } else if has!(mode, S_IXUSR) {
            'x'
        } else {
            '-'
        });

        result.push(if has!(mode, S_IRGRP) { 'r' } else { '-' });
        result.push(if has!(mode, S_IWGRP) { 'w' } else { '-' });
        result.push(if has!(mode, S_ISGID as mode_t) {
            if has!(mode, S_IXGRP) {
                's'
            } else {
                'S'
            }
        } else if has!(mode, S_IXGRP) {
            'x'
        } else {
            '-'
        });

        result.push(if has!(mode, S_IROTH) { 'r' } else { '-' });
        result.push(if has!(mode, S_IWOTH) { 'w' } else { '-' });
        result.push(if has!(mode, S_ISVTX as mode_t) {
            if has!(mode, S_IXOTH) {
                't'
            } else {
                'T'
            }
        } else if has!(mode, S_IXOTH) {
            'x'
        } else {
            '-'
        });

        result
    }

    /// Gets the permissions of the file displayed as an octal sequence of numbers.
    fn octal_permissions(&self) -> String {
        let mut octal_p = format!("{:o}", self.metadata.permissions().mode());
        if self.entry.file_type().is_file()
            || self.entry.file_type().is_socket()
            || self.entry.file_type().is_symlink()
        {
            for _ in 0..2 {
                octal_p.remove(0);
            }
        } else {
            octal_p.remove(0);
        }
        octal_p
    }

    /// Gets the name of the owner of the file.
    fn owner(&self) -> String {
        get_user_by_uid(self.metadata.uid())
            .unwrap()
            .name()
            .to_string_lossy()
            .to_string()
    }

    /// Gets the name of the group associated with the entry. Returns an empty string on macos.
    fn group(&self) -> String {
        get_group_by_gid(self.metadata.gid())
            // On macos, files can have no associated groups, in which case we return an empty string.
            .map_or(String::new(), |g| g.name().to_string_lossy().to_string())
    }

    /// Whether or not the file possesses extended attributes.
    fn has_xattr(&self) -> bool {
        // If we don't have permissions to read the file extended attributes then we ignore the
        // error and treat the file as having none.
        xattr::list(self.entry.path()).map_or(false, |x| x.peekable().peek().is_some())
    }

    /// Gets the time associated with the file (default is modified but can also be changed,
    /// accessed and created) and returns a date ready to be displayed.
    fn time(&self) -> String {
        let timestamp = match self.time {
            Time::Modified => UNIX_EPOCH + Duration::from_secs(self.metadata.mtime() as u64),
            Time::Changed => UNIX_EPOCH + Duration::from_secs(self.metadata.ctime() as u64),
            Time::Accessed => UNIX_EPOCH + Duration::from_secs(self.metadata.atime() as u64),
            Time::Created => self.metadata.created().unwrap(),
        };
        let date: DateTime<Local> = DateTime::from(timestamp);
        let year = date.format("%Y").to_string();
        if let Some(s) = self.time_style {
            return date.format(s).to_string();
        } else if year == CURRENT_YEAR.to_string() {
            return date.format("%b %e %H:%M").to_string();
        }
        date.format("%b %e %Y").to_string()
    }

    /// Gets the size of the file and returns a string ready to be displayed.
    fn size(&self) -> String {
        let bytes = self.metadata.size();
        if self.bytes_only {
            bytes.to_string()
        } else {
            match NumberPrefix::binary(bytes as f64) {
                NumberPrefix::Standalone(bytes) => format!("{bytes}"), // No unit specifier if it's
                // just bytes.
                NumberPrefix::Prefixed(prefix, n) => {
                    let mut prefix = prefix.symbol().to_string();
                    if prefix.ends_with('i') {
                        prefix = prefix.trim_end_matches('i').to_lowercase(); // Instead of Ki, Mi,
                                                                              // etc, we use k, m.
                    }

                    // Check whether we get more than 10 if we round up to the first decimal
                    // because we want do display 9.81 as "9.9", not as "10".
                    if (10.0 * n).ceil() >= 100.0 {
                        format!("{:.0}{}", n.ceil(), prefix)
                    } else {
                        format!("{:.1}{}", (10.0 * n).ceil() / 10.0, prefix)
                    }
                }
            }
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse().evaluate();
    let lscolors = LsColors::from_env().unwrap_or_default();
    let mut out = BufWriter::new(stdout());

    display_directory(&args.path, &args, &mut out, &lscolors)?;
    if args.recursive {
        let mut walker = WalkDir::new(&args.path).min_depth(1);
        if let Some(u) = args.max_depth {
            walker = walker.max_depth(u);
        }

        for entry in walker
            .into_iter()
            .filter_entry(|entry| args.all || !is_hidden(entry))
        {
            let entry = match entry {
                Ok(entry) => entry,
                Err(_) => continue, // We just ignore the entry if we don't have the right permissions.
            };
            let metadata = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue, // Same as above, we ignore the entry if we don't have the right
                                    // permissions.
            };
            if !metadata.is_dir() {
                continue; // We skip anything that isn't a directory.
            }

            let item = Item::new(entry, metadata, &args);

            display_directory(&item.entry.path(), &args, &mut out, &lscolors)?;
        }
    }

    out.flush()?; // BufWriter must be flushed before being dropped. Though it would be flushed
                  // durring dropping, any errors that would happen would not be signaled to us.

    Ok(())
}

/// Non-recursively walks a directory, puts its contents into a grid and display said grid.
///
/// # Errors
///
/// Returns an error if failed to write the grid to stdout.
fn display_directory<P>(
    path: &P,
    args: &Args,
    out: &mut BufWriter<io::Stdout>,
    lscolors: &LsColors,
) -> Result<()>
where
    P: AsRef<Path>,
{
    if path.as_ref().to_string_lossy() != args.path {
        writeln!(out, "\n{}:", path.as_ref().to_string_lossy())?; // Prints the path of the directory
                                                                  // that we are walkding if
                                                                  // it's not the top-level one.
    }

    let mut grid = Grid::new(GridOptions {
        filling: Filling::Spaces(2),
        direction: Direction::LeftToRight,
    });

    let mut additionnal_columns = 0; // Boths args.inode and args.octal permissions need us to add
                                     // an additionnal column to the grid.
    if args.inode {
        additionnal_columns += 1;
    }
    if args.octal_permissions {
        additionnal_columns += 1;
    }

    for entry in WalkDir::new(path)
        .min_depth(1)
        .max_depth(1)
        .into_iter()
        .filter_entry(|entry| args.all || !is_hidden(entry))
    {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue, // We just ignore the entry if we don't have the right permissions.
        };
        let metadata = match entry.metadata() {
            Ok(meta) => meta,
            Err(_) => continue, // Same as above, we ignore the entry if we don't have the right
                                // permissions.
        };
        let item = Item::new(entry, metadata, args);

        let matching = should_be_displayed(&item, args);
        if (!args.invert && matching) || (args.invert && !matching) {
            let entry_name = item.entry.file_name().to_string_lossy();

            if !args.should_use_colors && !args.long {
                grid.add(Cell::from(entry_name.to_string()));
            } else if args.should_use_colors && !args.long {
                let (contents, width) =
                    color_with_metadata(&entry_name, Some(&item.metadata), lscolors);
                grid.add(Cell { contents, width });
            } else if args.long {
                if args.inode {
                    grid.add(Cell::from(item.metadata.ino().to_string()));
                }
                if args.octal_permissions {
                    grid.add(Cell::from(item.octal_permissions()));
                }
                grid.add(Cell::from(format!(
                    "{}{}{}",
                    item.type_char(),
                    item.permission_string(),
                    if item.has_xattr() { "@" } else { "" }
                )));
                grid.add(Cell::from(item.metadata.nlink().to_string()));
                grid.add(Cell::from(item.owner().to_string()));
                grid.add(Cell::from(item.group().to_string()));
                grid.add(Cell::from(item.size()));
                grid.add(Cell::from(item.time()));

                if item.entry.file_type().is_symlink() {
                    let link = read_link(item.entry.path()).unwrap(); // Safe unwrap as we already
                                                                      // checked that the entry was
                                                                      // a symlink.
                    let pointing_to = link.to_str().unwrap().to_string();

                    if args.should_use_colors {
                        let pointing_to_metadata = PathBuf::from(&pointing_to).metadata().ok();
                        let (contents, width) = color_symlink_with_metadata(
                            &entry_name,
                            &pointing_to,
                            Some(&item.metadata),
                            pointing_to_metadata.as_ref(),
                            lscolors,
                        );
                        grid.add(Cell { contents, width });
                    } else {
                        grid.add(Cell::from(format!("{} -> {}", entry_name, pointing_to)));
                    }
                } else if !args.should_use_colors {
                    grid.add(Cell::from(entry_name.to_string()));
                } else {
                    let (contents, width) =
                        color_with_metadata(&entry_name, Some(&item.metadata), lscolors);
                    grid.add(Cell { contents, width });
                }
            }
        }
    }
    if args.long {
        write!(out, "{}", grid.fit_into_columns(7 + additionnal_columns))?;
    } else {
        write!(
            out,
            "{}",
            grid.fit_into_width(*DISPLAY_WIDTH)
                .unwrap_or_else(|| grid.fit_into_columns(1)) // If we can't fit the grid into the
                                                             // display we just print one entry per
                                                             // line.
        )?;
    }

    Ok(())
}

fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map_or(false, |s| s.starts_with('.'))
}

/// Whether or not the properties of the item matches with the command line arguments.
fn should_be_displayed(item: &Item<'_>, args: &Args) -> bool {
    type_matching(item, args.types.as_deref())
        && owner_matching(item, args.owner.as_deref())
        && group_matching(item, args.group.as_deref())
        && string_permissions_matching(item, args.permission_string.as_ref())
        && octal_permissions_matching(item, args.permission_number.as_ref())
        && hardlinks_matching(item, &args.hardlinks)
        && xattr_matching(item, args.attributes)
        && name_not_ignored(item, args.ignore.as_ref())
        && time_matching(item, args.match_time.as_ref())
        && size_matching(item, args.match_size.as_ref())
        && inode_matching(item, args.match_inode.as_ref())
}

/// Given a string s representing a file name or a file path, returns s colored and the length of s
/// without the color codes. We need to keep track of the length of s without the color codes so
/// that we can display them properly.
fn color_with_metadata(
    s: &str,
    metadata: Option<&Metadata>,
    lscolors: &LsColors,
) -> (String, usize) {
    lscolors
        .style_for_path_with_metadata(s, metadata)
        .map_or((s.to_string(), s.len()), |style| {
            (style.to_nu_ansi_term_style().paint(s).to_string(), s.len())
        })
}

/// Given a string s representing a symlink name or a symlink path, a string p representing the
/// path that the symlink is pointing to, and both of their metadata, returns a string 's -> p'
/// with s and p both colored and the length of the string 's -> p' without the color codes.
/// We need to keep track of the length without color codes so that we can display the string
/// properly.
fn color_symlink_with_metadata(
    s: &str,
    p: &str,
    s_metadata: Option<&Metadata>,
    p_metadata: Option<&Metadata>,
    lscolors: &LsColors,
) -> (String, usize) {
    let (colored_s, s_len) = color_with_metadata(s, s_metadata, lscolors);
    let (colored_p, p_len) = color_with_metadata(p, p_metadata, lscolors);
    (format!("{} -> {}", colored_s, colored_p), s_len + 4 + p_len)
}

fn name_not_ignored(item: &Item<'_>, ignore_pattern: Option<&Regex>) -> bool {
    ignore_pattern.is_none()
        || !ignore_pattern
            .unwrap()
            .is_match(item.entry.file_name().to_str().unwrap())
}

fn type_matching(item: &Item<'_>, types: Option<&[Type]>) -> bool {
    if types.is_none() {
        return true;
    }

    let mut matching = false;
    for c in types.unwrap().iter() {
        matching = match c {
            Type::File => {
                if item.entry.file_type().is_file() {
                    true
                } else {
                    matching
                }
            }
            Type::Directory => {
                if item.entry.file_type().is_dir() {
                    true
                } else {
                    matching
                }
            }
            Type::Symlink => {
                if item.entry.file_type().is_symlink() {
                    true
                } else {
                    matching
                }
            }
            Type::Block => {
                if item.entry.file_type().is_block_device() {
                    true
                } else {
                    matching
                }
            }
            Type::Character => {
                if item.entry.file_type().is_char_device() {
                    true
                } else {
                    matching
                }
            }
            Type::Fifo => {
                if item.entry.file_type().is_fifo() {
                    true
                } else {
                    matching
                }
            }
            Type::Socket => {
                if item.entry.file_type().is_socket() {
                    true
                } else {
                    matching
                }
            }
        }
    }
    matching
}

fn owner_matching(item: &Item<'_>, provided_owner: Option<&str>) -> bool {
    provided_owner.is_none() || provided_owner.unwrap() == item.owner()
}

fn group_matching(item: &Item<'_>, provided_group: Option<&str>) -> bool {
    provided_group.is_none() || provided_group.unwrap() == item.group()
}

fn string_permissions_matching(item: &Item<'_>, string_permissions: Option<&Regex>) -> bool {
    string_permissions.is_none()
        || string_permissions
            .unwrap()
            .is_match(&item.permission_string())
}

fn octal_permissions_matching(item: &Item<'_>, octal_permissions: Option<&Regex>) -> bool {
    octal_permissions.is_none()
        || octal_permissions
            .unwrap()
            .is_match(&item.octal_permissions())
}

fn hardlinks_matching(item: &Item<'_>, hardlinks: &Option<u64>) -> bool {
    hardlinks.is_none() || hardlinks.unwrap() == item.metadata.nlink()
}

fn xattr_matching(item: &Item<'_>, xattr: Option<bool>) -> bool {
    xattr.is_none() || xattr.unwrap() == item.has_xattr()
}

fn time_matching(item: &Item<'_>, time: Option<&Regex>) -> bool {
    time.is_none() || time.unwrap().is_match(&item.time())
}

fn size_matching(item: &Item<'_>, size: Option<&Regex>) -> bool {
    size.is_none() || size.unwrap().is_match(&item.size())
}

fn inode_matching(item: &Item<'_>, inode: Option<&Regex>) -> bool {
    inode.is_none() || inode.unwrap().is_match(&item.metadata.ino().to_string())
}
