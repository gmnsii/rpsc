use ansi_term::Color::{Blue, Cyan, Green, Purple, Red, White, Yellow};
use anyhow::{bail, ensure, Result};
use atty::Stream;
use clap::Parser;
use nix::unistd::{Gid, Group, Uid, User};
use regex::Regex;
use std::fs::{read_link, Metadata};
use std::io::StdoutLock;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::{io::Write, path::Path};
use walkdir::{DirEntry, WalkDir};

#[derive(Parser, Debug)]
#[command(version, max_term_width = 98)]
struct Args {
    /// Show items whose type match this argument ('.' or '-' for files, 'd' for directories, 'l' for
    /// symlinks, 'p' for fifo, 's' for socket, 'c' for character device, 'b' for block device).
    /// Can be specified multiple times to accept multiple types.
    #[arg(long = "type")]
    etype: Option<Vec<char>>,

    /// Recurse into directories.
    #[arg(short = 'R')]
    recursive: bool,

    /// Show hidden and 'dot' files.
    #[arg(short = 'a')]
    all: bool,

    /// Returns the results that doesn't match instead of the results that does.
    #[arg(long = "invert")]
    invert: bool,

    /// Whether or not rpsc should use colored output (auto, always, never)
    #[arg(long = "colors", default_value = "auto")]
    colors: String,

    /// Specify user permissions using a regex.
    #[arg(short = 'u')]
    user_permissions: Option<String>,

    /// Specify group permissions using a regex.
    #[arg(short = 'g')]
    group_permissions: Option<String>,

    /// Specify public permissions using a regex.
    #[arg(short = 'p')]
    public_permissions: Option<String>,

    /// Specify the user that must own the file.
    #[arg(long = "owner")]
    owner: Option<String>,

    /// Specify the group that must own the file. Not supported on macos.
    #[arg(long = "group")]
    group: Option<String>,

    /// The path of the directory that rpsc should search into.
    #[arg(default_value = ".")]
    path: String,
}

/// Represents a file system item.
struct Item {
    entry: DirEntry,
    extra_metadata: ItemMetadata,
}

impl Item {
    fn new(entry: DirEntry, metadata: Metadata) -> Self {
        let extra_metadata = ItemMetadata::new(&entry, &metadata);
        Self {
            entry,
            extra_metadata,
        }
    }
}

/// Represents the metadata of a file system item.
struct ItemMetadata {
    permission_string: String,
    type_char: char,
    owner: String,
    group: String,
}

impl ItemMetadata {
    fn new(entry: &DirEntry, metadata: &Metadata) -> Self {
        Self {
            permission_string: Self::get_permission_string(&entry, &metadata),
            type_char: Self::get_type_char(&entry),
            owner: Self::get_owner(&metadata),
            group: Self::get_group(&metadata),
        }
    }

    /// Takes a reference to an entry and returns the permissions of the entry as a string of
    /// letters and hyphens.
    ///
    /// # Panics
    ///
    /// Panics if one of the number of the numeric permissions of the entry is greater than 7, which
    /// should never happen.
    fn get_permission_string(entry: &DirEntry, metadata: &Metadata) -> String {
        let mut permissions_code = format!("{:o}", metadata.permissions().mode());

        // Permissions codes have a leading code to indicate file type that we don't want.
        if entry.file_type().is_dir()
            || entry.file_type().is_fifo()
            || entry.file_type().is_block_device()
            || entry.file_type().is_char_device()
        {
            for _ in 0..2 {
                permissions_code.remove(0);
            }
        } else {
            for _ in 0..3 {
                permissions_code.remove(0);
            }
        }
        permissions_code
            .chars()
            .map(|c| match c {
                '7' => "rwx",
                '6' => "rw-",
                '5' => "r-x",
                '4' => "r--",
                '3' => "-wx",
                '2' => "-w-",
                '1' => "--x",
                '0' => "---",
                _ => panic!("invalid permission"),
            })
            .collect::<String>()
    }

    /// Gets the type character used when printing the entry.
    ///
    /// # Panics
    ///
    /// Panics if the entry type is not recognized, which should never happen.
    fn get_type_char(entry: &DirEntry) -> char {
        if entry.file_type().is_file() {
            '.'
        } else if entry.file_type().is_dir() {
            'd'
        } else if entry.file_type().is_symlink() {
            'l'
        } else if entry.file_type().is_socket() {
            's'
        } else if entry.file_type().is_fifo() {
            'p'
        } else if entry.file_type().is_block_device() {
            'b'
        } else if entry.file_type().is_char_device() {
            'c'
        } else {
            unreachable!()
        }
    }

    /// Get the name of the owner of the file.
    ///
    /// # Panics
    ///
    /// Panics if failing to get the owner of the file, which should never happen as we check
    /// beforehand that we have the right permissions.
    fn get_owner(metadata: &Metadata) -> String {
        User::from_uid(Uid::from(metadata.uid()))
            .unwrap()
            .unwrap()
            .name
    }

    /// Gets the name of the group associated with the entry. Returns an empty string on macos.
    ///
    /// # Panics
    ///
    /// Panics if failing to get the associated group, which should never happen as we check
    /// beforehand that we have the right permissions.
    #[allow(unreachable_code)]
    #[allow(unused_variables)]
    fn get_group(metadata: &Metadata) -> String {
        #[cfg(target_os = "macos")]
        {
            return String::new();
        }

        Group::from_gid(Gid::from(metadata.gid()))
            .unwrap()
            .unwrap()
            .name
    }
}

/// # Errors
///
/// Returns an error if the `--group` argument was passed on macos.
/// Returns an error if the given path is invalid.
/// Returns an error if failed to construct a regex from arguments provided with `-u`, '-g' or
/// '-p'.
/// Some called functions can also returns errors, for reasons explained in their doc comment.
///
///  # Panics
///
///  Some called function can panic, for reasons explained in their doc comment.
fn main() -> Result<()> {
    let args = Args::parse();

    #[cfg(target_os = "macos")]
    {
        if args.group.is_some() {
            bail!("The --group argument is not supported on macos")
        }
    }
    ensure!(
        Path::new(&args.path).exists(),
        "\"{}\": No such file or directory (os error 2)",
        args.path
    );
    let user_permissions = match args.user_permissions {
        Some(s) => match Regex::new(&s) {
            Ok(re) => Some(re),
            Err(e) => bail!("\"{s}\": invalid user permissions: {e}"),
        },
        None => None,
    };
    let group_permissions = match args.group_permissions {
        Some(s) => match Regex::new(&s) {
            Ok(re) => Some(re),
            Err(e) => bail!("\"{s}\" invalid group permissions: {e}"),
        },
        None => None,
    };
    let public_permissions = match args.public_permissions {
        Some(s) => match Regex::new(&s) {
            Ok(re) => Some(re),
            Err(e) => bail!("\"{s}\": invalid public permissions: {e}"),
        },
        None => None,
    };

    let colors = match args.colors.as_str() {
        "always" => true,
        "never" => false,
        "auto" => {
            // Colors only if stdout is a tty.
            if atty::is(Stream::Stdout) {
                true
            } else {
                false
            }
        }
        _ => bail!(
            "\"{}\": invalid colors argument (must be auto, always or never)",
            args.colors
        ),
    };

    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    let walker = construct_walker(args.recursive, &args.path);

    for entry in walker
        .into_iter()
        .filter_entry(|entry| args.all || !is_hidden(entry))
    {
        if entry.is_err() {
            continue; // When we don't have permissions we just skip the entry.
        }
        let entry = entry.unwrap();
        let metadata = entry.metadata();
        if metadata.is_err() {
            continue; // Same as above, we ignore the entry if we don't have permissions.
        }
        let metadata = metadata.unwrap();
        let item = Item::new(entry, metadata);

        if args.recursive && item.entry.file_type().is_dir() {
            writeln!(lock, "\n{}:", item.entry.path().display())?; // Prints the directory we are currently walking.
        }

        let matching = type_matching(&item, &args.etype.as_deref())?
            && owner_matching(&item, &args.owner.as_deref())
            && group_matching(&item, &args.group.as_deref())
            && user_permissions_matching(&item, &user_permissions.as_ref())?
            && group_permissions_matching(&item, &group_permissions.as_ref())?
            && public_permissions_matching(&item, &public_permissions.as_ref())?;

        if (!args.invert && matching) || (args.invert && !matching) {
            print_entry(&mut lock, &item, colors)?;
        }
    }

    Ok(())
}

/// Returns a recursive walker with no max depth if `--recursive` is set, else returns a walker
/// with a max depth of 1.
fn construct_walker(recursive: bool, path: &str) -> WalkDir {
    let walker = WalkDir::new(path).min_depth(1);
    if recursive {
        return walker;
    }
    walker.max_depth(1)
}

/// Returns true if the entry name starts with a dot.
fn is_hidden(entry: &DirEntry) -> bool {
    entry
        .file_name()
        .to_str()
        .map(|s| s.starts_with('.'))
        .unwrap_or(false)
}

/// Determines if the typeof the given entry is matching with one of the given types.
///
/// # Errors
///
/// Returns an error if one of the given types is invalid.
fn type_matching(item: &Item, etype: &Option<&[char]>) -> Result<bool> {
    if etype.is_none() {
        return Ok(true);
    }

    let mut matching = false;
    for c in etype.as_ref().unwrap().iter() {
        matching = match c {
            '.' | '-' => {
                if item.entry.file_type().is_file() {
                    true
                } else {
                    matching
                }
            }
            'd' => {
                if item.entry.file_type().is_dir() {
                    true
                } else {
                    matching
                }
            }
            'l' => {
                if item.entry.file_type().is_symlink() {
                    true
                } else {
                    matching
                }
            }
            'b' => {
                if item.entry.file_type().is_block_device() {
                    true
                } else {
                    matching
                }
            }
            'c' => {
                if item.entry.file_type().is_char_device() {
                    true
                } else {
                    matching
                }
            }
            'p' => {
                if item.entry.file_type().is_fifo() {
                    true
                } else {
                    matching
                }
            }
            's' => {
                if item.entry.file_type().is_socket() {
                    true
                } else {
                    matching
                }
            }
            _ => bail!(
                "'{}': Invalid type argument (must be '.', '-', 'd', 'l', 'b', 'c', 'p' or 's')",
                c
            ),
        }
    }
    Ok(matching)
}

/// Determines if the owner associated with the given entry is matching with the given owner.
fn owner_matching(item: &Item, provided_owner: &Option<&str>) -> bool {
    if provided_owner.is_none() || provided_owner.unwrap() == item.extra_metadata.owner {
        return true;
    }
    false
}

/// Determines if the group associated with the given entry is matching with the given group.
fn group_matching(item: &Item, provided_group: &Option<&str>) -> bool {
    if provided_group.is_none() || provided_group.unwrap() == item.extra_metadata.group {
        return true;
    }
    false
}

/// Matches the given user permissions against the user permissions of the entry.
fn user_permissions_matching(item: &Item, user_permissions: &Option<&Regex>) -> Result<bool> {
    if user_permissions.is_none()
        || user_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[0..3])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Matches the given group permissions against the group permissions of the entry.
fn group_permissions_matching(item: &Item, group_permissions: &Option<&Regex>) -> Result<bool> {
    if group_permissions.is_none()
        || group_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[3..6])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Matches the given public permissions against the public permissions of the entry.
fn public_permissions_matching(item: &Item, public_permissions: &Option<&Regex>) -> Result<bool> {
    if public_permissions.is_none()
        || public_permissions
            .unwrap()
            .is_match(&item.extra_metadata.permission_string[6..9])
    {
        return Ok(true);
    }
    Ok(false)
}

/// Prints the entry file name, with different colors depending on its file type if colors is true.
///
/// # Errors
///
/// Returns an error when failing to write to stdout.
fn print_entry(lock: &mut StdoutLock, item: &Item, colors: bool) -> Result<()> {
    let ename = item.entry.file_name().to_str().unwrap();
    let displayed_string = format!(
        "{}{} {} {} {}",
        item.extra_metadata.type_char,
        item.extra_metadata.permission_string,
        item.extra_metadata.owner,
        item.extra_metadata.group,
        ename
    );

    if !colors {
        writeln!(lock, "{}", displayed_string)?;
    } else if item.entry.file_type().is_block_device() {
        writeln!(lock, "{}", Red.paint(displayed_string))?;
    } else if item.entry.file_type().is_char_device() {
        writeln!(lock, "{}", Yellow.paint(displayed_string))?;
    } else if item.entry.file_type().is_socket() {
        writeln!(lock, "{}", Green.paint(displayed_string))?;
    } else if item.entry.file_type().is_fifo() {
        writeln!(lock, "{}", Purple.paint(displayed_string))?;
    } else if item.entry.file_type().is_dir() {
        writeln!(lock, "{}", Blue.paint(displayed_string))?;
    } else if item.entry.file_type().is_symlink() {
        let link = read_link(item.entry.path()).unwrap();
        let pointing_to = link.to_str().unwrap();
        writeln!(
            lock,
            "{} -> {}",
            Cyan.paint(displayed_string),
            Cyan.paint(pointing_to)
        )?;
    } else {
        writeln!(lock, "{}", White.paint(displayed_string))?;
    }

    Ok(())
}
